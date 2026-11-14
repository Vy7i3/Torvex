//! Host configuration assessment, driven by the Python engine.
//!
//! The Python control catalogue is embedded in the binary (`include_str!`) and
//! materialised next to the system temporary directory on first use, so an
//! installed `torvex` has a working audit with no Python package to install and
//! no source checkout to point at.
//!
//! Torvex never reimplements the controls in Rust. The bridge's job is to run
//! the engine with a bounded timeout, validate the JSON, and convert failed or
//! advisory controls into [`Finding`]s. A missing interpreter is reported as an
//! audit error, not as a failed scan.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::findings::{Evidence, Finding, Severity, Source};

/// The audit engine, embedded so the binary is self-contained.
pub const EMBEDDED_AUDIT: &str = include_str!("../../python/torvex_audit.py");

/// Hard limit for one audit. A read-only audit of a normal filesystem takes a
/// few seconds; anything near this limit is a bug or a hostile mount.
const AUDIT_TIMEOUT: Duration = Duration::from_secs(120);

/// A parsed control result from the Python engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditControl {
    /// Stable control id such as `SSH-7401`.
    pub id: String,
    /// Short title.
    pub title: String,
    /// Category code such as `SSH`.
    pub category: String,
    /// Long category title.
    #[serde(default)]
    pub category_title: String,
    /// `passed`, `failed`, `suggestion`, `skipped` or `manual`.
    pub status: String,
    /// Severity label.
    pub severity: String,
    /// Wazuh-style level.
    pub level: u8,
    /// What the control describes.
    #[serde(default)]
    pub description: String,
    /// Why the control matters.
    #[serde(default)]
    pub rationale: String,
    /// How to fix a failure.
    #[serde(default)]
    pub remediation: String,
    /// Observed value.
    #[serde(default)]
    pub evidence: String,
    /// File or setting that was inspected.
    #[serde(default)]
    pub target: String,
    /// Indicative compliance mappings.
    #[serde(default)]
    pub compliance: Vec<String>,
    /// ATT&CK techniques.
    #[serde(default)]
    pub mitre: Vec<String>,
    /// Control weight.
    #[serde(default)]
    pub weight: f64,
    /// Points earned.
    #[serde(default)]
    pub earned: f64,
    /// Points available.
    #[serde(default)]
    pub possible: f64,
    /// Control kind: `config`, `scan` or `manual`.
    #[serde(default)]
    pub kind: String,
}

impl AuditControl {
    /// Parsed severity, defaulting to medium for unknown labels.
    pub fn severity(&self) -> Severity {
        Severity::parse(&self.severity).unwrap_or(Severity::Medium)
    }

    /// True for controls an analyst must act on or review.
    pub fn is_notable(&self) -> bool {
        matches!(self.status.as_str(), "failed" | "suggestion" | "manual")
    }

    /// Converts a notable control into a report finding.
    pub fn to_finding(&self) -> Option<Finding> {
        if !self.is_notable() {
            return None;
        }
        let mut severity = self.severity();
        if self.status == "manual" {
            severity = Severity::Info;
        }
        let mut finding = Finding::new(
            self.id.clone(),
            self.title.clone(),
            severity,
            Source::Audit,
            if self.target.is_empty() {
                self.category.clone()
            } else {
                self.target.clone()
            },
        )
        .with_description(if self.description.is_empty() {
            self.rationale.clone()
        } else {
            self.description.clone()
        })
        .with_evidence(vec![Evidence::new("observed", self.evidence.clone())])
        .with_tags(vec![
            self.category.clone(),
            "configuration".to_owned(),
            self.status.clone(),
        ])
        .with_mappings(self.mitre.clone(), self.compliance.clone());

        // A suggestion is advisory: keep it visible but below the failure band.
        if self.status == "suggestion" && finding.level > 5 {
            finding.level = 5;
            finding.severity = Severity::Low;
        }

        if !self.rationale.is_empty() {
            finding = finding.with_description(format!(
                "{}{}",
                if self.description.is_empty() {
                    String::new()
                } else {
                    format!("{} ", self.description)
                },
                self.rationale
            ));
        }
        if !self.remediation.is_empty() {
            finding = finding.with_remediation(self.remediation.clone());
        }
        Some(finding)
    }
}

/// Per-category score.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditCategory {
    /// Category code.
    pub id: String,
    /// Human title.
    #[serde(default)]
    pub title: String,
    /// 0-100 score, or null when nothing applied.
    #[serde(default)]
    pub score: Option<u32>,
    /// Controls that passed.
    #[serde(default)]
    pub passed: usize,
    /// Controls that failed or produced a suggestion.
    #[serde(default)]
    pub failed: usize,
    /// Controls that did not apply.
    #[serde(default)]
    pub skipped: usize,
    /// Points earned.
    #[serde(default)]
    pub earned: f64,
    /// Points available.
    #[serde(default)]
    pub possible: f64,
}

/// Hardening index and its inputs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditScore {
    /// 0-100 hardening index.
    pub index: u32,
    /// Points earned.
    #[serde(default)]
    pub earned: f64,
    /// Points available.
    #[serde(default)]
    pub possible: f64,
    /// Letter grade derived from the index.
    #[serde(default)]
    pub grade: String,
    /// Policy minimum.
    #[serde(default)]
    pub min_score: u32,
    /// True when the index is below the policy minimum.
    #[serde(default)]
    pub below_policy: bool,
}

/// Host identity recorded by the audit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditHost {
    /// Hostname.
    #[serde(default)]
    pub hostname: String,
    /// Operating system.
    #[serde(default)]
    pub system: String,
    /// Kernel release.
    #[serde(default)]
    pub release: String,
    /// Machine architecture.
    #[serde(default)]
    pub machine: String,
}

/// The Python engine's full report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// Schema identifier.
    pub schema: String,
    /// Engine name.
    pub engine: String,
    /// Engine version.
    pub engine_version: String,
    /// Policy name.
    pub policy: String,
    /// Policy version.
    #[serde(default)]
    pub policy_version: String,
    /// Root that was audited.
    pub root: String,
    /// True when the root was the live filesystem.
    #[serde(default)]
    pub live: bool,
    /// Host identity.
    #[serde(default)]
    pub host: AuditHost,
    /// Score summary.
    pub score: AuditScore,
    /// Per-category scores.
    #[serde(default)]
    pub categories: Vec<AuditCategory>,
    /// Status counters.
    #[serde(default)]
    pub counts: BTreeMap<String, usize>,
    /// Number of failed controls.
    #[serde(default)]
    pub warnings: usize,
    /// Number of advisory controls.
    #[serde(default)]
    pub suggestions: usize,
    /// Every control result.
    #[serde(default)]
    pub results: Vec<AuditControl>,
}

impl AuditReport {
    /// Converts every notable control into a finding.
    pub fn findings(&self) -> Vec<Finding> {
        self.results
            .iter()
            .filter_map(AuditControl::to_finding)
            .collect()
    }

    /// Controls with `failed` status, most severe first.
    pub fn failures(&self) -> Vec<&AuditControl> {
        let mut failures = self
            .results
            .iter()
            .filter(|control| control.status == "failed")
            .collect::<Vec<_>>();
        failures.sort_by_key(|control| std::cmp::Reverse(control.level));
        failures
    }
}

/// Options for one audit run.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Filesystem root to audit.
    pub root: PathBuf,
    /// Optional policy JSON file.
    pub policy: Option<PathBuf>,
    /// Control ids to skip.
    pub skip: Vec<String>,
    /// Explicit Python interpreter.
    pub python: Option<PathBuf>,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            policy: None,
            skip: Vec::new(),
            python: None,
        }
    }
}

/// Runs the audit and returns the parsed report.
pub fn run(options: &AuditOptions) -> Result<AuditReport> {
    let script = audit_script().context("could not prepare the audit engine")?;
    let python = python_interpreter(options.python.as_deref());

    let mut command = Command::new(&python);
    command
        .arg(&script)
        .arg("--root")
        .arg(&options.root)
        .arg("--format")
        .arg("json")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(policy) = &options.policy {
        command.arg("--policy").arg(policy);
    }
    for control in &options.skip {
        command.arg("--skip").arg(control);
    }

    let output = run_with_timeout(command, AUDIT_TIMEOUT).with_context(|| {
        format!(
            "failed to run the audit engine with {} (set TORVEX_PYTHON to choose an interpreter)",
            python.display()
        )
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        bail!(
            "audit engine exited with {}: {}",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".to_owned()),
            if detail.is_empty() {
                "no error output"
            } else {
                detail
            }
        );
    }

    let report: AuditReport =
        serde_json::from_slice(&output.stdout).context("audit engine returned malformed JSON")?;
    if report.schema != "torvex.audit.v1" {
        bail!(
            "audit engine returned schema {:?}, expected torvex.audit.v1",
            report.schema
        );
    }
    Ok(report)
}

/// Finds the audit script: an explicit override, then the embedded copy.
pub fn audit_script() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("TORVEX_AUDIT_SCRIPT") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "TORVEX_AUDIT_SCRIPT points at {}, which is not a file",
            path.display()
        );
    }

    let target = std::env::temp_dir().join(format!(
        "torvex_audit_{}.py",
        env!("CARGO_PKG_VERSION").replace('.', "_")
    ));
    if let Ok(existing) = fs::read(&target)
        && existing == EMBEDDED_AUDIT.as_bytes()
    {
        return Ok(target);
    }

    let temporary = target.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&temporary, EMBEDDED_AUDIT)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    fs::rename(&temporary, &target)
        .with_context(|| format!("failed to install {}", target.display()))?;
    Ok(target)
}

/// Chooses a Python interpreter, preferring an explicit setting.
pub fn python_interpreter(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Some(path) = std::env::var_os("TORVEX_PYTHON") {
        return PathBuf::from(path);
    }
    PathBuf::from("python3")
}

struct ProcessOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Runs a command with a deadline, capturing output through files so a chatty
/// child cannot deadlock on a full pipe.
fn run_with_timeout(mut command: Command, timeout: Duration) -> Result<ProcessOutput> {
    let stamp = format!(
        "{}_{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    );
    let out_path = std::env::temp_dir().join(format!("torvex_audit_{stamp}.out"));
    let err_path = std::env::temp_dir().join(format!("torvex_audit_{stamp}.err"));
    let out_file = fs::File::create(&out_path)?;
    let err_file = fs::File::create(&err_path)?;
    command.stdout(Stdio::from(out_file));
    command.stderr(Stdio::from(err_file));

    let mut child = command.spawn().map_err(|error| {
        anyhow!("{error}. Install Python 3.10 or newer, or point TORVEX_PYTHON at an interpreter")
    })?;
    let started = Instant::now();

    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if started.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(&out_path);
                let _ = fs::remove_file(&err_path);
                bail!(
                    "audit engine exceeded the {} second limit",
                    timeout.as_secs()
                );
            }
            None => sleep(Duration::from_millis(20)),
        }
    };

    let stdout = fs::read(&out_path).unwrap_or_default();
    let stderr = fs::read(&err_path).unwrap_or_default();
    let _ = fs::remove_file(&out_path);
    let _ = fs::remove_file(&err_path);

    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn python_available() -> bool {
        Command::new(python_interpreter(None))
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[test]
    fn control_conversion_keeps_guidance() {
        let control = AuditControl {
            id: "SSH-7401".to_owned(),
            title: "SSH root login is restricted".to_owned(),
            category: "SSH".to_owned(),
            category_title: "SSH server".to_owned(),
            status: "failed".to_owned(),
            severity: "high".to_owned(),
            level: 8,
            description: "PermitRootLogin yes".to_owned(),
            rationale: "Root login removes accountability.".to_owned(),
            remediation: "Set PermitRootLogin no.".to_owned(),
            evidence: "PermitRootLogin yes".to_owned(),
            target: "/etc/ssh/sshd_config".to_owned(),
            compliance: vec!["CIS 5.2.8".to_owned()],
            mitre: vec!["T1078".to_owned()],
            weight: 1.0,
            earned: 0.0,
            possible: 1.0,
            kind: "config".to_owned(),
        };
        let finding = control.to_finding().expect("finding");
        assert_eq!(finding.source, Source::Audit);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.target, "/etc/ssh/sshd_config");
        assert!(finding.description.contains("Root login"));
        assert_eq!(
            finding.remediation.as_deref(),
            Some("Set PermitRootLogin no.")
        );
        assert_eq!(finding.mitre, vec!["T1078"]);
    }

    #[test]
    fn passed_and_skipped_controls_are_not_findings() {
        let mut control = AuditControl {
            id: "X".to_owned(),
            title: "X".to_owned(),
            category: "SSH".to_owned(),
            category_title: String::new(),
            status: "passed".to_owned(),
            severity: "low".to_owned(),
            level: 3,
            description: String::new(),
            rationale: String::new(),
            remediation: String::new(),
            evidence: String::new(),
            target: String::new(),
            compliance: Vec::new(),
            mitre: Vec::new(),
            weight: 1.0,
            earned: 1.0,
            possible: 1.0,
            kind: "config".to_owned(),
        };
        assert!(control.to_finding().is_none());
        control.status = "skipped".to_owned();
        assert!(control.to_finding().is_none());
        control.status = "suggestion".to_owned();
        control.severity = "high".to_owned();
        let finding = control.to_finding().expect("suggestion becomes a finding");
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.level <= 5);
    }

    #[test]
    fn embedded_script_materialises() {
        let path = audit_script().expect("materialise script");
        let content = fs::read_to_string(&path).expect("read script");
        assert!(content.contains("torvex_audit"));
        assert!(content.contains("SSH-7401"));
    }

    #[test]
    fn runs_a_hermetic_audit_when_python_exists() {
        if !python_available() {
            eprintln!("skipping: python3 is not available");
            return;
        }
        let temp = tempfile::tempdir().expect("temp dir");
        let report = run(&AuditOptions {
            root: temp.path().to_path_buf(),
            ..AuditOptions::default()
        })
        .expect("audit an empty root");
        assert_eq!(report.engine, "torvex_audit");
        assert!(!report.results.is_empty());
        assert!(!report.live);
        assert_eq!(report.score.index, 0);
    }

    #[test]
    fn a_bad_root_is_reported_not_panicked() {
        if !python_available() {
            return;
        }
        let report = run(&AuditOptions {
            root: PathBuf::from("/definitely/not/a/real/root"),
            ..AuditOptions::default()
        });
        assert!(report.is_err());
    }
}
