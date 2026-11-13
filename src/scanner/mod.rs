//! File and directory traversal.
//!
//! A directory scan is best-effort: unreadable entries are recorded and the
//! scan continues. Symlinks inside a directory tree are not followed, avoiding
//! loops and unexpected traversal outside the requested root. An explicitly
//! requested symlink to a file is scanned; a symlink to a directory is walked
//! once at its resolved location.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

use crate::detection::{DetectionEngine, YaraEngine};
use crate::engine::{FailureKind, ScanFailure, ScanReport, ScanResult, Verdict};
use crate::utils::fingerprint_file;

/// Options that control how a path is scanned.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Explicit YARA rules directory. `None` uses engine auto-detection.
    pub rules_dir: Option<PathBuf>,
}

/// Scans a file or directory with default options.
pub fn scan_path(path: &Path) -> Result<ScanReport> {
    scan_path_with_options(path, &ScanOptions::default())
}

/// Scans a file or recursively scans a directory.
///
/// Returns an error only when the scan cannot start (for example, the root
/// path is missing or the configured rules cannot be loaded). Per-file and
/// per-directory failures are collected in [`ScanReport::failures`].
pub fn scan_path_with_options(path: &Path, options: &ScanOptions) -> Result<ScanReport> {
    let metadata =
        fs::metadata(path).with_context(|| format!("cannot access {}", path.display()))?;

    let engine = YaraEngine::new(options.rules_dir.as_deref())?;
    let mut report = ScanReport::new(path.display().to_string(), engine.info().clone());

    if metadata.is_file() {
        scan_file(path, &engine, &mut report);
        return Ok(report);
    }

    if !metadata.is_dir() {
        bail!("{} is not a regular file or directory", path.display());
    }

    let walk_root = directory_walk_root(path)?;
    for entry in WalkDir::new(&walk_root).follow_links(false) {
        match entry {
            Ok(entry) => {
                if entry.file_type().is_dir() {
                    continue;
                }
                if entry.file_type().is_file() {
                    scan_file(entry.path(), &engine, &mut report);
                } else {
                    report.skipped += 1;
                }
            }
            Err(error) => {
                let failed_path = error
                    .path()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| path.to_path_buf());
                report.failures.push(ScanFailure {
                    path: failed_path.display().to_string(),
                    kind: FailureKind::Walk,
                    error: error.to_string(),
                });
            }
        }
    }

    Ok(report)
}

fn scan_file(path: &Path, engine: &YaraEngine, report: &mut ScanReport) {
    let fingerprint = match fingerprint_file(path) {
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

    match engine.scan_file(path) {
        Ok(matches) => {
            let verdict = if matches.is_empty() {
                Verdict::Clean
            } else {
                Verdict::Suspicious
            };
            report.results.push(ScanResult {
                path: path.display().to_string(),
                sha256: fingerprint.sha256,
                size: fingerprint.size,
                file_type: fingerprint.file_type,
                verdict,
                matches,
            });
        }
        Err(error) => {
            report.failures.push(ScanFailure {
                path: path.display().to_string(),
                kind: FailureKind::Detect,
                error: format!("{error:#}"),
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
