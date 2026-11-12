use std::path::Path;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use eframe::egui::{self, Color32, RichText};

use crate::engine::{ScanResult, Verdict};
use crate::scanner::scan_path;

type ScanOutcome = Result<Vec<ScanResult>, String>;

pub fn run() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Torvex",
        options,
        Box::new(|_creation_context| Ok(Box::new(TorvexApp::default()))),
    )
}

#[derive(Default)]
struct TorvexApp {
    path: String,
    show_clean_files: bool,
    is_scanning: bool,
    receiver: Option<Receiver<ScanOutcome>>,
    results: Vec<ScanResult>,
    error: Option<String>,
}

impl TorvexApp {
    fn start_scan(&mut self) {
        let path = self.path.trim().to_owned();
        if path.is_empty() {
            self.error = Some("Enter a file or folder path to scan.".to_owned());
            return;
        }

        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);
        self.results.clear();
        self.error = None;
        self.is_scanning = true;

        thread::spawn(move || {
            let outcome = scan_path(Path::new(&path)).map_err(|error| format!("{error:#}"));
            let _ = sender.send(outcome);
        });
    }

    fn poll_scan(&mut self, context: &egui::Context) {
        let message = match self.receiver.as_ref() {
            Some(receiver) => match receiver.try_recv() {
                Ok(outcome) => Some(outcome),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Err(
                    "The scan worker stopped before returning results.".to_owned(),
                )),
            },
            None => None,
        };

        if let Some(outcome) = message {
            self.receiver = None;
            self.is_scanning = false;
            match outcome {
                Ok(results) => self.results = results,
                Err(error) => self.error = Some(error),
            }
        }

        if self.is_scanning {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    fn result_counts(&self) -> (usize, usize, usize) {
        self.results.iter().fold((0, 0, 0), |mut counts, result| {
            match result.status {
                Verdict::Clean => counts.0 += 1,
                Verdict::Suspicious => counts.1 += 1,
                Verdict::Malicious => counts.2 += 1,
            }
            counts
        })
    }
}

impl eframe::App for TorvexApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        self.poll_scan(&context);

        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Torvex");
            ui.label("Local file scanner");
            ui.add_space(12.0);

            ui.label("File or folder path");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.path)
                        .hint_text("/path/to/file-or-folder")
                        .desired_width(f32::INFINITY),
                );
                if ui
                    .add_enabled(!self.is_scanning, egui::Button::new("Use current folder"))
                    .clicked()
                {
                    match std::env::current_dir() {
                        Ok(path) => self.path = path.display().to_string(),
                        Err(error) => self.error = Some(format!("Could not read current folder: {error}")),
                    }
                }
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.is_scanning, egui::Button::new("Scan"))
                    .clicked()
                {
                    self.start_scan();
                }
                if ui
                    .add_enabled(!self.is_scanning, egui::Button::new("Clear results"))
                    .clicked()
                {
                    self.results.clear();
                    self.error = None;
                }
                if self.is_scanning {
                    ui.spinner();
                    ui.label(format!("Scanning {}…", self.path));
                }
            });

            if let Some(error) = &self.error {
                ui.add_space(8.0);
                ui.colored_label(Color32::LIGHT_RED, error);
            }

            if !self.results.is_empty() {
                let (clean, suspicious, malicious) = self.result_counts();
                ui.add_space(18.0);
                ui.separator();
                ui.heading("Scan summary");
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("Files scanned: {}", self.results.len()));
                    ui.separator();
                    ui.colored_label(Color32::LIGHT_GREEN, format!("Clean: {clean}"));
                    ui.separator();
                    ui.colored_label(Color32::YELLOW, format!("Suspicious: {suspicious}"));
                    ui.separator();
                    ui.colored_label(Color32::LIGHT_RED, format!("Malicious: {malicious}"));
                });

                ui.add_space(10.0);
                ui.checkbox(&mut self.show_clean_files, "Show clean files");
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for result in &self.results {
                            if result.status == Verdict::Clean && !self.show_clean_files {
                                continue;
                            }
                            self.show_result(ui, result);
                        }
                    });
            }

            ui.add_space(12.0);
            ui.separator();
            ui.label(
                RichText::new(
                    "YARA matches are shown as suspicious. Confidence is not calibrated yet; example rules are test fixtures only.",
                )
                .small()
                .weak(),
            );
        });
    }
}

impl TorvexApp {
    fn show_result(&self, ui: &mut egui::Ui, result: &ScanResult) {
        let color = match result.status {
            Verdict::Clean => Color32::LIGHT_GREEN,
            Verdict::Suspicious => Color32::YELLOW,
            Verdict::Malicious => Color32::LIGHT_RED,
        };

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(color, result.status.to_string());
                ui.strong(&result.path);
            });
            ui.label(
                RichText::new(format!("SHA-256: {}", result.sha256))
                    .monospace()
                    .small(),
            );
            ui.label(format!(
                "Size: {} bytes  ·  Type: {}  ·  Confidence: {}",
                result.size,
                result.file_type.as_deref().unwrap_or("unknown"),
                result
                    .confidence
                    .map(|value| format!("{value:.2}"))
                    .unwrap_or_else(|| "not calibrated".to_owned())
            ));
            if let Some(reason) = &result.reason {
                ui.label(format!("Reason: {reason}"));
            }
        });
        ui.add_space(4.0);
    }
}
