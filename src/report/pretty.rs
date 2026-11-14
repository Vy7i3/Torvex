//! Terminal report renderer.
//!
//! The layout is deliberately scan-first: verdict, risk, then the findings an
//! analyst should read, then evidence. Colour is opt-out (`--no-color` or
//! `NO_COLOR`) so piping to a file never produces escape sequences.

use std::fmt::Write as _;

use crate::engine::ScanReport;
use crate::findings::{Severity, Source};
use crate::utils::{format_bytes, format_duration};

/// Renders the human report.
pub fn render_pretty(report: &ScanReport, color: bool) -> String {
    let paint = Painter { enabled: color };
    let summary = &report.summary;
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{} {}  {}",
        paint.bold("Torvex"),
        paint.dim(report.version.as_str()),
        paint.dim("local-first security scan")
    );
    let _ = writeln!(out, "Target   {}", report.root);
    let _ = writeln!(
        out,
        "Engines  {}{}",
        engine_summary(report),
        if report.correlated > 0 {
            format!("  ·  {} correlated", report.correlated)
        } else {
            String::new()
        }
    );
    if report.engines.yara {
        let _ = writeln!(
            out,
            "Rules    {}",
            if report.rules.source.is_empty() {
                "none".to_owned()
            } else {
                format!("{} ({})", report.rules.source, report.rules.describe())
            }
        );
    }
    if report.rules.demo_rule_count > 0 {
        let _ = writeln!(
            out,
            "{}",
            paint.yellow(&format!(
                "Note     {} of {} rules are demo fixtures, not detection content.",
                report.rules.demo_rule_count, report.rules.rule_count
            ))
        );
    }
    let _ = writeln!(
        out,
        "Scanned  {}{} in {} ({})",
        summary.scanned,
        if summary.scanned == 1 {
            " file"
        } else {
            " files"
        },
        format_duration(std::time::Duration::from_millis(report.duration_ms)),
        format_bytes(summary.bytes_scanned)
    );
    let _ = writeln!(out);

    // -- risk ------------------------------------------------------------
    let risk = summary.risk_score;
    let risk_label = match risk {
        0 => paint.green("no risk points"),
        1..=20 => paint.green("low"),
        21..=45 => paint.yellow("moderate"),
        46..=70 => paint.orange("elevated"),
        _ => paint.red("high"),
    };
    let _ = writeln!(
        out,
        "{}  {}  {}/100  {}",
        paint.bold("RISK    "),
        bar(risk, 24),
        risk,
        risk_label
    );
    let _ = writeln!(
        out,
        "        {} findings: {}",
        summary.findings,
        severity_breakdown(report, &paint)
    );

    if let Some(audit) = &report.audit {
        let index = audit.score.index;
        let _ = writeln!(
            out,
            "{}  {}  {}/100  grade {}  ({} warnings, {} suggestions)",
            paint.bold("HOST    "),
            bar(index, 24),
            index,
            audit.score.grade,
            audit.warnings,
            audit.suggestions
        );
        let _ = writeln!(
            out,
            "        policy {} on {}{}",
            audit.policy,
            audit.root,
            if audit.live { " (live)" } else { " (snapshot)" }
        );
    } else if let Some(error) = &report.audit_error {
        let _ = writeln!(
            out,
            "{}",
            paint.yellow(&format!("Audit    not run: {error}"))
        );
    }
    let _ = writeln!(out);

    // -- findings --------------------------------------------------------
    if report.findings.is_empty() {
        let _ = writeln!(out, "{}", paint.green("No findings."));
        if summary.scanned == 0 {
            let _ = writeln!(out, "No files were successfully scanned.");
        }
    } else {
        let _ = writeln!(
            out,
            "{}",
            paint.bold(&format!("Findings ({})", report.findings.len()))
        );
        for finding in &report.findings {
            let label = format!("{:<8}", finding.severity.as_str().to_uppercase());
            let _ = writeln!(
                out,
                "  {} {}  {}",
                paint.severity(finding.severity, &label),
                paint.bold(&finding.title),
                paint.dim(&format!("[{}]", finding.id))
            );
            let _ = writeln!(out, "           {}", finding.target);
            if !finding.description.is_empty() {
                let _ = writeln!(out, "           {}", paint.dim(&finding.description));
            }
            if !finding.evidence.is_empty() {
                let evidence = finding
                    .evidence
                    .iter()
                    .map(|entry| format!("{}={}", entry.kind, entry.value))
                    .collect::<Vec<_>>()
                    .join("  ");
                let _ = writeln!(out, "           {}", paint.dim(&evidence));
            }
            let mut meta = Vec::new();
            if !finding.mitre.is_empty() {
                meta.push(format!("ATT&CK {}", finding.mitre.join(" ")));
            }
            if !finding.compliance.is_empty() {
                meta.push(finding.compliance.join(", "));
            }
            if finding.demo {
                meta.push("demo fixture".to_owned());
            }
            if !meta.is_empty() {
                let _ = writeln!(out, "           {}", paint.dim(&meta.join("  ·  ")));
            }
            if let Some(remediation) = &finding.remediation {
                let _ = writeln!(out, "           {} {}", paint.green("fix:"), remediation);
            }
            let _ = writeln!(out);
        }
    }

    // -- audit detail ----------------------------------------------------
    if let Some(audit) = &report.audit {
        let failures = audit.failures();
        if !failures.is_empty() {
            let _ = writeln!(
                out,
                "{}",
                paint.bold(&format!("Host warnings ({})", failures.len()))
            );
            for control in failures {
                let label = format!("{:<8}", control.severity.to_uppercase());
                let level = Severity::parse(&control.severity).unwrap_or(Severity::Medium);
                let _ = writeln!(
                    out,
                    "  {} {}  {}",
                    paint.severity(level, &label),
                    control.title,
                    paint.dim(&format!("[{}]", control.id))
                );
                if !control.evidence.is_empty() {
                    let _ = writeln!(out, "           {}", paint.dim(&control.evidence));
                }
                if !control.remediation.is_empty() {
                    let _ = writeln!(
                        out,
                        "           {} {}",
                        paint.green("fix:"),
                        control.remediation
                    );
                }
            }
            let _ = writeln!(out);
        }
    }

    // -- files ------------------------------------------------------------
    let suspicious = report.top_files(8);
    if !suspicious.is_empty() {
        let _ = writeln!(out, "{}", paint.bold("Files with findings"));
        for file in suspicious {
            let severity = file.top_severity().unwrap_or(Severity::Info);
            let _ = writeln!(
                out,
                "  {} {}",
                paint.severity(
                    severity,
                    &format!("{:<8}", severity.as_str().to_uppercase())
                ),
                file.path
            );
            let mut detail = vec![format_bytes(file.size)];
            if let Some(kind) = &file.file_type {
                detail.push(kind.clone());
            }
            if let Some(analysis) = &file.analysis {
                if let Some(kind) = &analysis.kind {
                    detail.push(kind.clone());
                }
                detail.push(format!("entropy {:.2}", analysis.entropy));
                if !analysis.iocs.is_empty() {
                    detail.push(format!("{} indicator(s)", analysis.iocs.len()));
                }
            }
            detail.push(format!(
                "sha256 {}",
                &file.sha256[..16.min(file.sha256.len())]
            ));
            let _ = writeln!(out, "           {}", paint.dim(&detail.join("  ·  ")));
            for rule in file.matches.iter().take(6) {
                let _ = writeln!(
                    out,
                    "           {} {}",
                    paint.dim(rule.engine.as_str()),
                    rule.title
                );
            }
            if file.matches.len() > 6 {
                let _ = writeln!(out, "           {}", paint.dim("…"));
            }
            let _ = writeln!(out);
        }
    }

    // -- failures ---------------------------------------------------------
    if !report.failures.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            paint.red(&format!(
                "Incomplete scan ({} failures)",
                report.failures.len()
            ))
        );
        for failure in &report.failures {
            let _ = writeln!(out, "  [{}] {}", failure.kind, failure.path);
            let _ = writeln!(out, "           {}", paint.dim(&failure.error));
        }
        let _ = writeln!(
            out,
            "  Files listed above were not fully checked, so the scan is not clean."
        );
        let _ = writeln!(out);
    }

    let _ = writeln!(
        out,
        "{}",
        paint.dim(
            "A finding is evidence to review, not proof of malware. A clean result only means no loaded rule matched. Torvex is not an antivirus."
        )
    );
    out
}

fn engine_summary(report: &ScanReport) -> String {
    let mut parts = Vec::new();
    if report.engines.yara {
        parts.push(format!("YARA {}", report.rules.describe()));
    }
    if report.engines.native {
        parts.push(format!(
            "native {} rules ({})",
            report.engines.native_rules, report.engines.native_version
        ));
    }
    if report.engines.audit {
        parts.push("host audit".to_owned());
    }
    if parts.is_empty() {
        parts.push("no engines enabled".to_owned());
    }
    parts.join("  ·  ")
}

fn severity_breakdown(report: &ScanReport, paint: &Painter) -> String {
    let mut parts = Vec::new();
    for severity in Severity::ALL.iter().rev() {
        let count = report
            .summary
            .by_severity
            .get(severity.as_str())
            .copied()
            .unwrap_or(0);
        if count == 0 {
            continue;
        }
        parts.push(paint.severity(*severity, &format!("{count} {}", severity.as_str())));
    }
    if parts.is_empty() {
        return "none".to_owned();
    }
    parts.join(", ")
}

fn bar(value: u32, width: usize) -> String {
    let filled = ((value as usize).min(100) * width) / 100;
    let mut out = String::with_capacity(width);
    for index in 0..width {
        out.push(if index < filled { '█' } else { '░' });
    }
    out
}

struct Painter {
    enabled: bool,
}

impl Painter {
    fn wrap(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("{code}{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.wrap("\x1b[1m", text)
    }

    fn dim(&self, text: &str) -> String {
        self.wrap("\x1b[2m", text)
    }

    fn green(&self, text: &str) -> String {
        self.wrap("\x1b[32m", text)
    }

    fn yellow(&self, text: &str) -> String {
        self.wrap("\x1b[33m", text)
    }

    fn orange(&self, text: &str) -> String {
        self.wrap("\x1b[38;5;208m", text)
    }

    fn red(&self, text: &str) -> String {
        self.wrap("\x1b[1;31m", text)
    }

    fn severity(&self, severity: Severity, text: &str) -> String {
        self.wrap(severity.ansi(), text)
    }
}

/// Source label padded for the file detail list.
pub fn source_label(source: Source) -> &'static str {
    match source {
        Source::Yara => "yara   ",
        Source::Native => "native ",
        Source::Audit => "audit  ",
        Source::Correlation => "corr   ",
    }
}
