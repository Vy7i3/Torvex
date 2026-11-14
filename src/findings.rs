//! The unified finding model.
//!
//! Every engine speaks this type: YARA-X matches, native indicators, host audit
//! controls and correlated findings all become a [`Finding`]. That lets one
//! report, one risk score and one HTML dashboard cover a file scan and a host
//! audit without special cases.
//!
//! Severity carries two numbers on purpose:
//!
//! * [`Severity`] is the human label and the grouping used by the UI.
//! * [`Finding::level`] is a Wazuh-style `0..=15` value used for sorting,
//!   thresholds (`--fail-on`, `--min-level`) and correlation rules.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Severity of a single finding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Context only; never affects the risk score.
    #[default]
    Info,
    /// Hygiene issue or weak hardening with limited direct impact.
    Low,
    /// A real weakness that needs review, such as missing ASLR or no auditd.
    Medium,
    /// A credible path to compromise or a strong malicious indicator.
    High,
    /// Immediate risk: active backdoor pattern, empty passwords, exposed keys.
    Critical,
}

impl Severity {
    /// Ordered from least to most severe.
    pub const ALL: [Self; 5] = [
        Self::Info,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    /// Wazuh-style level used for sorting and thresholds.
    pub fn level(self) -> u8 {
        match self {
            Self::Info => 1,
            Self::Low => 3,
            Self::Medium => 6,
            Self::High => 8,
            Self::Critical => 10,
        }
    }

    /// Maps a numeric level back to a severity band.
    pub fn from_level(level: u8) -> Self {
        match level {
            0..=2 => Self::Info,
            3..=5 => Self::Low,
            6..=7 => Self::Medium,
            8..=9 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Lowercase label used in JSON and CSS classes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Points contributed to the 0-100 risk score.
    ///
    /// The formula is deliberately simple and documented in the README:
    /// `risk = min(100, sum(points))` with critical 35, high 18, medium 7,
    /// low 2 and info 0. Demo fixtures contribute nothing.
    pub fn risk_points(self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 2,
            Self::Medium => 7,
            Self::High => 18,
            Self::Critical => 35,
        }
    }

    /// ANSI colour used by the terminal report.
    pub fn ansi(self) -> &'static str {
        match self {
            Self::Info => "\x1b[36m",
            Self::Low => "\x1b[32m",
            Self::Medium => "\x1b[33m",
            Self::High => "\x1b[38;5;208m",
            Self::Critical => "\x1b[1;31m",
        }
    }

    /// Parses a severity name, accepting common aliases.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" | "none" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "moderate" | "warn" | "warning" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which engine produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// YARA-X rule match.
    Yara,
    /// Native C++ indicator or structural analysis.
    Native,
    /// Python host configuration assessment.
    Audit,
    /// A correlation rule that fired over other findings.
    Correlation,
}

impl Source {
    /// Stable lowercase label used in JSON and the dashboard.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yara => "yara",
            Self::Native => "native",
            Self::Audit => "audit",
            Self::Correlation => "correlation",
        }
    }

    /// Parses the JSON label.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "yara" => Some(Self::Yara),
            "native" => Some(Self::Native),
            "audit" => Some(Self::Audit),
            "correlation" => Some(Self::Correlation),
            _ => None,
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One piece of supporting evidence for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// What the value represents, such as `offset` or `file mode`.
    pub kind: String,
    /// The observed value, already rendered for display.
    pub value: String,
}

impl Evidence {
    /// Creates evidence from any displayable pair.
    pub fn new(kind: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            value: value.into(),
        }
    }
}

/// A single, engine-independent finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier: a rule name, a native indicator id, or a control id.
    pub id: String,
    /// Short human title.
    pub title: String,
    /// What was observed and why it matters.
    pub description: String,
    /// Human severity label.
    pub severity: Severity,
    /// Numeric level, `0..=15`.
    pub level: u8,
    /// Producing engine.
    pub source: Source,
    /// File path or host control target.
    pub target: String,
    /// Optional grouping such as the audit category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Supporting evidence, already formatted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Free-form tags used by correlation rules and the UI filters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// MITRE ATT&CK technique identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre: Vec<String>,
    /// Indicative compliance mappings (CIS, PCI DSS, NIST).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compliance: Vec<String>,
    /// Concrete remediation step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// True when the finding comes from a harmless demo fixture.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub demo: bool,
    /// Findings that produced a correlated finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
}

impl Finding {
    /// Creates a finding, deriving the numeric level from the severity.
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        source: Source,
        target: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: String::new(),
            severity,
            level: severity.level(),
            source,
            target: target.into(),
            category: None,
            evidence: Vec::new(),
            tags: Vec::new(),
            mitre: Vec::new(),
            compliance: Vec::new(),
            remediation: None,
            demo: false,
            related: Vec::new(),
        }
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Sets the remediation guidance.
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Replaces the evidence list.
    pub fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Adds tags.
    pub fn with_tags(mut self, tags: impl IntoIterator<Item = String>) -> Self {
        self.tags = tags.into_iter().collect();
        self
    }

    /// Adds ATT&CK and compliance mappings.
    pub fn with_mappings(
        mut self,
        mitre: impl IntoIterator<Item = String>,
        compliance: impl IntoIterator<Item = String>,
    ) -> Self {
        self.mitre = mitre.into_iter().collect();
        self.compliance = compliance.into_iter().collect();
        self
    }

    /// Marks the finding as a demo fixture.
    pub fn as_demo(mut self) -> Self {
        self.demo = true;
        self
    }

    /// Points this finding contributes to the risk score.
    pub fn risk_points(&self) -> u32 {
        if self.demo {
            0
        } else {
            self.severity.risk_points()
        }
    }

    /// Sort key: most severe first, then engine, identifier and target.
    pub fn sort_key(&self) -> (std::cmp::Reverse<u8>, &'static str, &str, &str) {
        (
            std::cmp::Reverse(self.level),
            self.source.as_str(),
            self.id.as_str(),
            self.target.as_str(),
        )
    }
}

/// Computes the documented 0-100 risk score for a set of findings.
pub fn risk_score(findings: &[Finding]) -> u32 {
    findings
        .iter()
        .map(Finding::risk_points)
        .sum::<u32>()
        .min(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_levels_and_labels_round_trip() {
        for severity in Severity::ALL {
            assert_eq!(Severity::from_level(severity.level()), severity);
            assert_eq!(Severity::parse(severity.as_str()), Some(severity));
        }
    }

    #[test]
    fn risk_score_is_capped_and_ignores_demo_fixtures() {
        let critical = Finding::new("a", "a", Severity::Critical, Source::Yara, "f");
        let demo = Finding::new("b", "b", Severity::Critical, Source::Yara, "f").as_demo();
        assert_eq!(risk_score(std::slice::from_ref(&demo)), 0);
        assert_eq!(risk_score(std::slice::from_ref(&critical)), 35);
        let many = vec![critical; 5];
        assert_eq!(risk_score(&many), 100);
    }

    #[test]
    fn findings_sort_by_severity_first() {
        let mut findings = [
            Finding::new("low", "low", Severity::Low, Source::Yara, "a"),
            Finding::new("crit", "crit", Severity::Critical, Source::Yara, "b"),
            Finding::new("med", "med", Severity::Medium, Source::Yara, "c"),
        ];
        findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        assert_eq!(findings[0].id, "crit");
        assert_eq!(findings[0].level, 10);
        assert_eq!(findings[2].id, "low");
    }

    #[test]
    fn findings_serialise_without_empty_noise() {
        let finding = Finding::new("id", "title", Severity::Low, Source::Native, "x");
        let json = serde_json::to_value(&finding).expect("serialise");
        assert_eq!(json["severity"], "low");
        assert_eq!(json["source"], "native");
        assert!(json.get("demo").is_none());
        assert!(json.get("evidence").is_none());
    }
}
