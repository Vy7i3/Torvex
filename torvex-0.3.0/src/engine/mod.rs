//! Types shared by the scanner, detection engines, CLI, GUI and reports.
//!
//! A scan produces both the per-file detail ([`ScanResult`]) and a flat,
//! de-duplicated list of [`Finding`]s from every engine. The flat list is what
//! the risk score, the CLI, the dashboard and the correlation engine consume.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::audit::AuditReport;
use crate::findings::{Evidence, Finding, Severity, Source, risk_score};

/// The report schema version. Bumped when the JSON shape changes.
pub const SCHEMA: &str = "torvex.report.v2";

/// The outcome of scanning one file.
///
/// Torvex deliberately has no `malicious` verdict. A rule match is
/// [`Verdict::Suspicious`]: evidence to review, not proof of malware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No loaded rule matched.
    Clean,
    /// At least one rule or indicator matched.
    Suspicious,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
        })
    }
}

/// One matching rule or indicator for a file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Engine that produced the match.
    pub engine: Source,
    /// Rule identifier (YARA rule name or native indicator id).
    pub rule: String,
    /// YARA namespace, or the native catalogue name.
    pub namespace: String,
    /// Short human title.
    pub title: String,
    /// Severity assigned by the rule or its metadata.
    pub severity: Severity,
    /// Wazuh-style numeric level.
    pub level: u8,
    /// Tags attached to the rule.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Rule `description` metadata, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the rule declares itself as a harmless demo fixture.
    #[serde(default)]
    pub demo: bool,
    /// Supporting evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// MITRE ATT&CK identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre: Vec<String>,
    /// Indicative compliance mappings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compliance: Vec<String>,
    /// Remediation guidance from the rule metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl RuleMatch {
    /// Converts a file match into a report finding for `path`.
    pub fn to_finding(&self, path: &str) -> Finding {
        let mut finding = Finding::new(
            self.rule.clone(),
            self.title.clone(),
            self.severity,
            self.engine,
            path,
        )
        .with_description(
            self.description
                .clone()
                .unwrap_or_else(|| format!("{} matched {}", self.rule, path)),
        )
        .with_evidence(self.evidence.clone())
        .with_tags(self.tags.clone())
        .with_mappings(self.mitre.clone(), self.compliance.clone());

        if let Some(remediation) = &self.remediation {
            finding = finding.with_remediation(remediation.clone());
        }
        if self.demo {
            finding = finding.as_demo();
        }
        finding
    }
}

/// An indicator extracted from file content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ioc {
    /// `url`, `email` or `ipv4`.
    pub kind: String,
    /// The extracted value.
    pub value: String,
    /// Byte offset of the first occurrence.
    pub offset: usize,
}

/// Structural and statistical facts about one file, produced by the native core.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FileAnalysis {
    /// Container kind: `elf64`, `pe32+`, `macho64`, `script` or `unknown`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Machine architecture when it could be determined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Word size in bits, or zero when unknown.
    #[serde(default)]
    pub bits: u8,
    /// Shannon entropy over the whole scanned buffer.
    #[serde(default)]
    pub entropy: f64,
    /// Worst 4 KiB window entropy, an indicator of packing or encryption.
    #[serde(default)]
    pub max_window_entropy: f64,
    /// Longest run of base64 alphabet characters.
    #[serde(default)]
    pub longest_base64_run: usize,
    /// Extracted indicators, capped by the native core.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub iocs: Vec<Ioc>,
    /// True when only a prefix of the file was analysed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Evidence and file metadata for one successfully scanned file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    /// Path as displayed to the user.
    pub path: String,
    /// Lowercase hexadecimal SHA-256 of every byte that was read.
    pub sha256: String,
    /// Number of bytes in the file.
    pub size: u64,
    /// MIME type estimated from the header, with an extension fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    /// Scan verdict.
    pub verdict: Verdict,
    /// Matching rules, most severe first.
    #[serde(default)]
    pub matches: Vec<RuleMatch>,
    /// Native structural analysis, when that engine ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis: Option<FileAnalysis>,
}

impl ScanResult {
    /// Returns `true` when at least one rule matched.
    pub fn is_suspicious(&self) -> bool {
        self.verdict == Verdict::Suspicious
    }

    /// Highest severity among the matches, if any.
    pub fn top_severity(&self) -> Option<Severity> {
        self.matches.iter().map(|entry| entry.severity).max()
    }
}

/// The stage at which a file or directory could not be fully processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The directory tree could not be read.
    Walk,
    /// The file could not be opened, hashed, or inspected.
    Read,
    /// A detection engine failed on the file.
    Detect,
    /// The audit engine failed.
    Audit,
}

impl std::fmt::Display for FailureKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Walk => "walk",
            Self::Read => "read",
            Self::Detect => "detect",
            Self::Audit => "audit",
        })
    }
}

/// A file, directory or engine that could not be fully processed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanFailure {
    /// Path as displayed to the user.
    pub path: String,
    /// Stage that failed.
    pub kind: FailureKind,
    /// Human-readable error details.
    pub error: String,
}

/// Where the active YARA rule set came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleSetInfo {
    /// Human-readable source label.
    pub source: String,
    /// Rules directory, if external rules were loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_dir: Option<String>,
    /// Number of compiled rules.
    pub rule_count: usize,
    /// Number of compiled rules that declare themselves as demo fixtures.
    pub demo_rule_count: usize,
}

impl Default for RuleSetInfo {
    fn default() -> Self {
        Self {
            source: "none".to_owned(),
            rules_dir: None,
            rule_count: 0,
            demo_rule_count: 0,
        }
    }
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

/// Which engines were active for a scan.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EngineStatus {
    /// YARA-X content rules were loaded and evaluated.
    pub yara: bool,
    /// The native C++ indicator engine ran.
    pub native: bool,
    /// The Python host audit ran.
    pub audit: bool,
    /// Native core version reported by the C++ library.
    #[serde(default)]
    pub native_version: String,
    /// Number of native indicator rules registered.
    #[serde(default)]
    pub native_rules: usize,
}

/// Aggregated counters for a finished scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Files that were read and scanned.
    pub scanned: usize,
    /// Files with no matching rules.
    pub clean: usize,
    /// Files with at least one matching rule.
    pub suspicious: usize,
    /// Files or directories that could not be processed.
    pub errors: usize,
    /// Non-regular entries skipped during traversal.
    pub skipped: usize,
    /// Directories skipped by the ignore list.
    #[serde(default)]
    pub ignored_dirs: usize,
    /// Total bytes read from successfully scanned files.
    pub bytes_scanned: u64,
    /// Number of findings across every engine.
    #[serde(default)]
    pub findings: usize,
    /// Findings per severity label, including zero entries.
    #[serde(default)]
    pub by_severity: BTreeMap<String, usize>,
    /// Documented 0-100 risk score.
    #[serde(default)]
    pub risk_score: u32,
    /// Host hardening index when the audit ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_index: Option<u32>,
}

/// The complete result of scanning a file or directory tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Schema identifier, so consumers can reject incompatible reports.
    pub schema: String,
    /// Tool name.
    pub tool: String,
    /// Tool version.
    pub version: String,
    /// UTC timestamp of report creation.
    pub generated_at: String,
    /// Wall-clock scan duration.
    pub duration_ms: u64,
    /// Root path that was requested by the user.
    pub root: String,
    /// Engines that ran.
    pub engines: EngineStatus,
    /// Active YARA rule set metadata.
    pub rules: RuleSetInfo,
    /// Summary counters.
    pub summary: ScanSummary,
    /// Successfully scanned files.
    pub results: Vec<ScanResult>,
    /// Every finding, including audit and correlated findings.
    pub findings: Vec<Finding>,
    /// Number of correlated findings inside `findings`.
    #[serde(default)]
    pub correlated: usize,
    /// Per-entry failures.
    pub failures: Vec<ScanFailure>,
    /// Non-regular entries skipped during traversal.
    pub skipped: usize,
    /// Host audit report, when the audit engine ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditReport>,
    /// Why the audit engine did not produce a report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_error: Option<String>,
}

impl ScanReport {
    /// Creates an empty report for `root` using `rules`.
    pub fn new(root: String, rules: RuleSetInfo) -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            tool: "torvex".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            generated_at: crate::utils::utc_timestamp(),
            duration_ms: 0,
            root,
            engines: EngineStatus::default(),
            rules,
            summary: ScanSummary::default(),
            results: Vec::new(),
            findings: Vec::new(),
            correlated: 0,
            failures: Vec::new(),
            skipped: 0,
            audit: None,
            audit_error: None,
        }
    }

    /// Recomputes the summary from the current results and findings.
    pub fn refresh_summary(&mut self) {
        let mut summary = ScanSummary {
            errors: self.failures.len(),
            skipped: self.skipped,
            findings: self.findings.len(),
            risk_score: risk_score(&self.findings),
            audit_index: self.audit.as_ref().map(|audit| audit.score.index),
            ..ScanSummary::default()
        };

        for severity in Severity::ALL {
            summary.by_severity.insert(severity.as_str().to_owned(), 0);
        }
        for finding in &self.findings {
            *summary
                .by_severity
                .entry(finding.severity.as_str().to_owned())
                .or_insert(0) += 1;
        }

        for result in &self.results {
            summary.scanned += 1;
            summary.bytes_scanned += result.size;
            match result.verdict {
                Verdict::Clean => summary.clean += 1,
                Verdict::Suspicious => summary.suspicious += 1,
            }
        }

        self.summary = summary;
    }

    /// Returns the summary computed by the last [`ScanReport::refresh_summary`].
    pub fn summary(&self) -> ScanSummary {
        self.summary.clone()
    }

    /// Returns `true` when at least one finding or suspicious file exists.
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty() || self.results.iter().any(ScanResult::is_suspicious)
    }

    /// Returns `true` when every discovered entry was processed.
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }

    /// Findings at or above `level`, sorted most severe first.
    pub fn findings_at_least(&self, level: u8) -> Vec<&Finding> {
        let mut findings = self
            .findings
            .iter()
            .filter(|finding| finding.level >= level)
            .collect::<Vec<_>>();
        findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        findings
    }

    /// Files with the highest severity, for the CLI and dashboard.
    pub fn top_files(&self, limit: usize) -> Vec<&ScanResult> {
        let mut files = self
            .results
            .iter()
            .filter(|result| result.is_suspicious())
            .collect::<Vec<_>>();
        files.sort_by_key(|result| {
            (
                std::cmp::Reverse(result.top_severity().map(Severity::level).unwrap_or(0)),
                result.path.as_str(),
            )
        });
        files.truncate(limit);
        files
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
            analysis: None,
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
        report.refresh_summary();

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

    #[test]
    fn severity_buckets_include_every_level() {
        let mut report = ScanReport::new("root".to_owned(), RuleSetInfo::default());
        report
            .findings
            .push(Finding::new("x", "x", Severity::High, Source::Native, "f"));
        report.refresh_summary();
        assert_eq!(report.summary.by_severity.get("high"), Some(&1));
        assert_eq!(report.summary.by_severity.get("critical"), Some(&0));
        assert_eq!(report.summary.risk_score, 18);
    }

    #[test]
    fn findings_are_filtered_by_level() {
        let mut report = ScanReport::new("root".to_owned(), RuleSetInfo::default());
        report
            .findings
            .push(Finding::new("low", "low", Severity::Low, Source::Yara, "f"));
        report.findings.push(Finding::new(
            "crit",
            "crit",
            Severity::Critical,
            Source::Yara,
            "f",
        ));
        let filtered = report.findings_at_least(8);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "crit");
    }
}
