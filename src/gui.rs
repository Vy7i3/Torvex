//! `eframe` desktop interface.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};

use crate::engine::{ScanReport, ScanResult, Verdict};
use crate::scanner::{ScanOptions, scan_path_with_options};
use crate::utils::{format_bytes, format_duration};

type ScanOutcome = Result<ScanReport, String>;

/// Opens the desktop scanner.
pub fn run(initial_rules_dir: Option<PathBuf>) -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 760.0])
            .with_min_inner_size([640.0, 480.0])
            .with_title("Torvex"),
        ..Default::default()
    };

    eframe::run_native(
        "Torvex",
        options,
        Box::new(move |_creation_context| Ok(Box::new(TorvexApp::new(initial_rules_dir)))),
    )
}

struct TorvexApp {
    path: String,
    rules_dir: String,
    active_path: String,
    show_clean_files: bool,
    is_scanning: bool,
    scan_started: Option<Instant>,
    last_duration: Option<Duration>,
    receiver: Option<Receiver<ScanOutcome>>,
    report: Option<ScanReport>,
    error: Option<String>,
}

impl TorvexApp {
    fn new(initial_rules_dir: Option<PathBuf>) -> Self {
        let path = std::env::current_dir()
            .map(|directory| directory.display().to_string())
            .unwrap_or_default();
        let rules_dir = initial_rules_dir
            .map(|directory| directory.display().to_string())
            .unwrap_or_default();

        Self {
            path,
            rules_dir,
            active_path: String::new(),
            show_clean_files: false,
            is_scanning: false,
            scan_started: None,
            last_duration: None,
            receiver: None,
            report: None,
            error: None,
        }
    }

    fn start_scan(&mut self) {
        let path = self.path.trim().to_owned();
        if path.is_empty() {
            self.error = Some("Enter a file or folder path to scan.".to_owned());
            return;
        }

        let rules_dir = self.rules_dir.trim();
        let options = ScanOptions {
            rules_dir: (!rules_dir.is_empty()).then(|| PathBuf::from(rules_dir)),
        };

        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);
        self.report = None;
        self.error = None;
        self.is_scanning = true;
        self.active_path = path.clone();
        self.scan_started = Some(Instant::now());
        self.last_duration = None;

        thread::spawn(move || {
            let outcome = scan_path_with_options(Path::new(&path), &options)
                .map_err(|error| format!("{error:#}"));
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
            self.last_duration = self.scan_started.take().map(|start| start.elapsed());
            match outcome {
                Ok(report) => self.report = Some(report),
                Err(error) => self.error = Some(error),
            }
        }

        if self.is_scanning {
            context.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn accept_dropped_path(&mut self, context: &egui::Context) {
        if self.is_scanning {
            return;
        }

        let dropped = context.input(|input| {
            input
                .raw
                .dropped_files
                .first()
                .map(|file| file.path().to_path_buf())
        });

        if let Some(path) = dropped {
            self.path = path.display().to_string();
            self.error = None;
        }
    }
}

impl eframe::App for TorvexApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        self.accept_dropped_path(&context);
        self.poll_scan(&context);

        let mut scan_requested = false;

        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Torvex");
                ui.label(RichText::new("experimental alpha").small().weak());
            });
            ui.label("Local-first file scanner. Not an antivirus.");
            ui.add_space(12.0);

            ui.label("File or folder");
            let path_response = ui.add(
                egui::TextEdit::singleline(&mut self.path)
                    .hint_text("/path/to/file-or-folder")
                    .desired_width(f32::INFINITY),
            );
            if !self.is_scanning
                && path_response.lost_focus()
                && ui.input(|input| input.key_pressed(egui::Key::Enter))
            {
                scan_requested = true;
            }

            ui.add_space(6.0);
            ui.label("Rules directory (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.rules_dir)
                    .hint_text("auto-detect: TORVEX_RULES_DIR, ./rules, or embedded demo rules")
                    .desired_width(f32::INFINITY),
            );
            ui.label(
                RichText::new(
                    "Leave blank to auto-detect. An insecure or untrusted rule directory can be dangerous; only load rules you trust.",
                )
                .small()
                .weak(),
            );

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.is_scanning, egui::Button::new("Scan"))
                    .clicked()
                {
                    scan_requested = true;
                }
                if ui
                    .add_enabled(!self.is_scanning, egui::Button::new("Use current folder"))
                    .clicked()
                {
                    match std::env::current_dir() {
                        Ok(directory) => {
                            self.path = directory.display().to_string();
                        }
                        Err(error) => {
                            self.error = Some(format!(
                                "Could not read the current folder: {error}"
                            ));
                        }
                    }
                }
                if ui
                    .add_enabled(!self.is_scanning, egui::Button::new("Clear results"))
                    .clicked()
                {
                    self.report = None;
                    self.error = None;
                    self.last_duration = None;
                }
                if self.is_scanning {
                    ui.spinner();
                    let elapsed = self
                        .scan_started
                        .map(|start| start.elapsed())
                        .unwrap_or_default();
                    ui.label(format!(
                        "Scanning {} ({})",
                        self.active_path,
                        format_duration(elapsed)
                    ));
                }
            });

            if let Some(error) = &self.error {
                ui.add_space(8.0);
                ui.colored_label(Color32::LIGHT_RED, error);
            }

            if self.report.is_some() {
                ui.add_space(12.0);
                ui.separator();
                self.show_report(ui);
            }

            ui.add_space(10.0);
            ui.separator();
            ui.label(
                RichText::new(
                    "YARA matches are suspicious evidence, not confirmed malware. Demo rules are harmless test fixtures. Torvex does not assign a calibrated confidence score, and a clean result is not proof that a file is safe.",
                )
                .small()
                .weak(),
            );
        });

        if scan_requested {
            self.start_scan();
        }
    }
}

impl TorvexApp {
    fn show_report(&mut self, ui: &mut egui::Ui) {
        let Some(report) = &self.report else {
            return;
        };

        let summary = report.summary();
        ui.heading("Scan summary");
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "Scanned: {} {}",
                summary.scanned,
                if summary.scanned == 1 {
                    "file"
                } else {
                    "files"
                }
            ));
            if let Some(duration) = self.last_duration {
                ui.label(format!("in {}", format_duration(duration)));
            }
            ui.label(format!("({})", format_bytes(summary.bytes_scanned)));
            ui.separator();
            ui.colored_label(Color32::LIGHT_GREEN, format!("Clean: {}", summary.clean));
            ui.separator();
            ui.colored_label(
                Color32::YELLOW,
                format!("Suspicious: {}", summary.suspicious),
            );
            if summary.errors > 0 {
                ui.separator();
                ui.colored_label(Color32::LIGHT_RED, format!("Errors: {}", summary.errors));
            }
            if summary.skipped > 0 {
                ui.separator();
                ui.label(format!("Skipped: {}", summary.skipped));
            }
        });

        ui.add_space(4.0);
        ui.label(format!(
            "Rules: {} ({})",
            report.rules.source,
            report.rules.describe()
        ));
        if report.rules.demo_rule_count > 0 {
            ui.colored_label(
                Color32::YELLOW,
                format!(
                    "{} of {} loaded rules are demo fixtures, not malware signatures.",
                    report.rules.demo_rule_count, report.rules.rule_count
                ),
            );
        }

        if !report.failures.is_empty() {
            ui.add_space(6.0);
            egui::CollapsingHeader::new(format!("Scan errors ({})", report.failures.len()))
                .default_open(true)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(
                            "These entries were not fully checked. The scan is incomplete.",
                        )
                        .small()
                        .weak(),
                    );
                    for failure in &report.failures {
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(format!("[{}] {}", failure.kind, failure.path))
                                .monospace(),
                        );
                        ui.label(RichText::new(&failure.error).small().weak());
                    }
                });
        }

        ui.add_space(8.0);
        ui.checkbox(&mut self.show_clean_files, "Show clean files");
        ui.add_space(4.0);

        let list_height = (ui.available_height() - 80.0).max(120.0);
        let mut visible = 0;
        egui::ScrollArea::vertical()
            .max_height(list_height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for result in &report.results {
                    if result.verdict == Verdict::Clean
                        && !self.show_clean_files
                    {
                        continue;
                    }
                    visible += 1;
                    show_result(ui, result);
                }

                if visible == 0 {
                    if report.results.is_empty() {
                        ui.label("No regular files were scanned.");
                    } else {
                        ui.label(
                            "No suspicious files. A clean result only means that no loaded rule matched.",
                        );
                    }
                }
            });
    }
}

fn show_result(ui: &mut egui::Ui, result: &ScanResult) {
    let color = match result.verdict {
        Verdict::Clean => Color32::LIGHT_GREEN,
        Verdict::Suspicious => Color32::YELLOW,
    };

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(color, result.verdict.to_string());
            ui.add(egui::Label::new(RichText::new(&result.path).strong()).wrap());
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("SHA-256: {}", result.sha256))
                    .monospace()
                    .small(),
            );
            if ui
                .small_button("Copy hash")
                .on_hover_text("Copy the SHA-256 hash to the clipboard")
                .clicked()
            {
                ui.ctx().copy_text(result.sha256.clone());
            }
        });
        ui.label(format!(
            "Size: {}  ·  Type: {}",
            format_bytes(result.size),
            result.file_type.as_deref().unwrap_or("unknown")
        ));

        for rule_match in &result.matches {
            ui.add_space(4.0);
            ui.label(RichText::new(format!("Rule: {}", rule_match.rule)).strong());
            let mut details = vec![format!("namespace: {}", rule_match.namespace)];
            if rule_match.demo {
                details.push("demo fixture".to_owned());
            }
            if !rule_match.tags.is_empty() {
                details.push(format!("tags: {}", rule_match.tags.join(", ")));
            }
            ui.label(RichText::new(details.join("  ·  ")).small().weak());
            if let Some(description) = &rule_match.description {
                ui.label(description);
            }
        }
    });
    ui.add_space(4.0);
}
