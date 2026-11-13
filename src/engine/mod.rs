//! Types shared by the scanner, detection engines, CLI, and GUI.

use serde::Serialize;

/// The outcome of scanning one file.
///
/// Torvex deliberately has no "malicious" verdict yet. A YARA rule match is
/// reported as [`Verdict::Suspicious`], because a single rule match is evidence
/// to review, not proof of malware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No loaded rule matched.
    Clean,
    /// At least one loaded rule matched.
    Suspicious,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
        };
        formatter.write_str(label)
    }
}

/// One YARA rule that matched a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleMatch {
    /// Rule identifier.
    pub rule: String,
    /// YARA namespace the rule was compiled in.
    pub namespace: String,
    /// Tags attached to the rule.
    pub tags: Vec<String>,
    /// The rule's `description` metadata, when present.
    pub description: Option<String>,
    /// Whether the rule declares itself as a harmless demo fixture.
    pub demo: bool,
}

/// Evidence and file metadata for one successfully scanned file.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// Path as displayed to the user. Paths that are not valid UTF-8 are
    /// rendered lossily, matching the behavior of [`std::path::Path::display`].
    pub path: String,
    /// Lowercase hexadecimal SHA-256 of the bytes that were read.
    pub sha256: String,
    /// Number of bytes that were read.
    pub size: u64,
    /// MIME type estimated from the file header, with an extension fallback.
    pub file_type: Option<String>,
    /// Scan verdict.
    pub verdict: Verdict,
    /// Matching rules, sorted by rule name.
    pub matches: Vec<RuleMatch>,
}

impl ScanResult {
    /// Returns `true` when at least one rule matched.
    pub fn is_suspicious(&self) -> bool {
        self.verdict == Verdict::Suspicious
    }
}

/// The stage at which a file or directory could not be fully processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The directory tree could not be read.
    Walk,
    /// The file could not be opened, hashed, or inspected.
    Read,
    /// The detection engine failed to scan the file.
    Detect,
}

impl std::fmt::Display for FailureKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Walk => "walk",
            Self::Read => "read",
            Self::Detect => "detect",
        };
        formatter.write_str(label)
    }
}

/// A file or directory that could not be scanned.
///
/// Failures are collected per entry so one unreadable file does not stop a
/// directory scan. A completed scan with failures is incomplete, not clean.
#[derive(Debug, Clone, Serialize)]
pub struct ScanFailure {
    /// Path as displayed to the user.
    pub path: String,
    /// Stage that failed.
    pub kind: FailureKind,
    /// Human-readable error details.
    pub error: String,
}

/// Where the active YARA rule set came from.
#[derive(Debug, Clone, Serialize)]
pub struct RuleSetInfo {
    /// Human-readable source label: the rules directory, or
    /// `"embedded demo rules"` when the built-in fallback is in use.
    pub source: String,
    /// Rules directory, if external rules were loaded.
    pub rules_dir: Option<String>,
    /// Number of compiled rules.
    pub rule_count: usize,
    /// Number of compiled rules that declare themselves as demo fixtures.
    pub demo_rule_count: usize,
}

impl RuleSetInfo {
    /// Returns `true` when every loaded rule is a demo fixture.
    pub fn is_demo_only(&self) -> bool {
        self.rule_count > 0 && self.demo_rule_count == self.rule_count
    }

    /// Returns a compact description such as `"3 rules, all demo fixtures"`.
    pub fn describe(&self) -> String {
        let mut description = format!(
            "{} {}",
            self.rule_count,
            if self.rule_count == 1 {
                "rule"
            } else {
                "rules"
            }
        );

        if self.demo_rule_count > 0 {
            if self.is_demo_only() {
                description.push_str(", all demo fixtures");
            } else {
                description.push_str(&format!(
                    ", {} demo {}",
                    self.demo_rule_count,
                    if self.demo_rule_count == 1 {
                        "fixture"
                    } else {
                        "fixtures"
                    }
                ));
            }
        }

        description
    }
}

/// Aggregated counters for a finished scan.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ScanSummary {
    /// Files that were read and scanned.
    pub scanned: usize,
    /// Files with no matching rules.
    pub clean: usize,
    /// Files with at least one matching rule.
    pub suspicious: usize,
    /// Files or directories that could not be processed.
    pub errors: usize,
    /// Non-regular entries skipped during directory traversal.
    pub skipped: usize,
    /// Total bytes read from successfully scanned files.
    pub bytes_scanned: u64,
}

/// The complete result of scanning a file or directory tree.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// Root path that was requested by the user.
    pub root: String,
    /// Active rule set metadata.
    pub rules: RuleSetInfo,
    /// Successfully scanned files.
    pub results: Vec<ScanResult>,
    /// Per-entry failures.
    pub failures: Vec<ScanFailure>,
    /// Non-regular entries skipped during traversal.
    pub skipped: usize,
}

impl ScanReport {
    /// Creates an empty report for `root` using `rules`.
    pub fn new(root: String, rules: RuleSetInfo) -> Self {
        Self {
            root,
            rules,
            results: Vec::new(),
            failures: Vec::new(),
            skipped: 0,
        }
    }

    /// Computes summary counters.
    pub fn summary(&self) -> ScanSummary {
        let mut summary = ScanSummary {
            errors: self.failures.len(),
            skipped: self.skipped,
            ..ScanSummary::default()
        };

        for result in &self.results {
            summary.scanned += 1;
            summary.bytes_scanned += result.size;
            match result.verdict {
                Verdict::Clean => summary.clean += 1,
                Verdict::Suspicious => summary.suspicious += 1,
            }
        }

        summary
    }

    /// Returns `true` when at least one file is suspicious.
    pub fn has_findings(&self) -> bool {
        self.results.iter().any(ScanResult::is_suspicious)
    }

    /// Returns `true` when every discovered entry was processed.
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_result() -> ScanResult {
        ScanResult {
            path: "clean.txt".to_owned(),
            sha256: "a".repeat(64),
            size: 10,
            file_type: Some("text/plain".to_owned()),
            verdict: Verdict::Clean,
            matches: Vec::new(),
        }
    }

    #[test]
    fn summary_counts_results_failures_and_skipped_entries() {
        let mut report = ScanReport::new(
            "fixtures".to_owned(),
            RuleSetInfo {
                source: "embedded demo rules".to_owned(),
                rules_dir: None,
                rule_count: 3,
                demo_rule_count: 3,
            },
        );
        report.results.push(clean_result());
        report.failures.push(ScanFailure {
            path: "locked.txt".to_owned(),
            kind: FailureKind::Read,
            error: "permission denied".to_owned(),
        });
        report.skipped = 2;

        let summary = report.summary();
        assert_eq!(summary.scanned, 1);
        assert_eq!(summary.clean, 1);
        assert_eq!(summary.suspicious, 0);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.skipped, 2);
        assert_eq!(summary.bytes_scanned, 10);
        assert!(!report.is_complete());
        assert!(!report.has_findings());
    }

    #[test]
    fn demo_only_requires_at_least_one_rule() {
        let info = RuleSetInfo {
            source: "embedded demo rules".to_owned(),
            rules_dir: None,
            rule_count: 0,
            demo_rule_count: 0,
        };
        assert!(!info.is_demo_only());
    }
}
