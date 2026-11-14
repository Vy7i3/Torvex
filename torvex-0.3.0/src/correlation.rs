//! Finding correlation, modelled on the Wazuh rule engine.
//!
//! Wazuh rules match decoded events and can fire a higher-level rule when a
//! lower one repeats (`frequency`, `timeframe`) or when a parent rule matched
//! (`if_sid`). Torvex applies the same idea to findings instead of log events:
//!
//! * `ids` is the `if_sid` equivalent — select findings by identifier, with a
//!   trailing `*` acting as a prefix wildcard.
//! * `frequency` + `same_target` is the repeat rule: "three high findings in
//!   one file is one incident, not three".
//! * `require_sources` and `require_tags` are composite rules: they only fire
//!   when different engines agree on the same scan.
//!
//! A correlated finding is evidence *about* other findings, so it is always
//! produced with [`Source::Correlation`] and lists what it was built from.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::findings::{Evidence, Finding, Severity, Source};

/// One correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    /// Stable identifier, reported as the finding id.
    pub id: String,
    /// Short title.
    pub title: String,
    /// Why the combination matters.
    #[serde(default)]
    pub description: String,
    /// Severity of the correlated finding.
    #[serde(default = "default_severity")]
    pub severity: Severity,
    /// Only consider findings from these sources.
    #[serde(default)]
    pub sources: Vec<Source>,
    /// Only consider findings with these ids (exact, or `PREFIX*`).
    #[serde(default)]
    pub ids: Vec<String>,
    /// Only consider findings carrying at least one of these tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Ignore findings below this level.
    #[serde(default)]
    pub min_level: u8,
    /// Minimum number of matching findings before the rule fires.
    #[serde(default = "default_frequency")]
    pub frequency: usize,
    /// Require every match to share one target (one file or one control path).
    #[serde(default)]
    pub same_target: bool,
    /// Every listed source must appear among the matches.
    #[serde(default)]
    pub require_sources: Vec<Source>,
    /// Every listed tag must appear among the matches.
    #[serde(default)]
    pub require_tags: Vec<String>,
    /// Remediation guidance for the combined finding.
    #[serde(default)]
    pub remediation: Option<String>,
    /// ATT&CK techniques for the combined finding.
    #[serde(default)]
    pub mitre: Vec<String>,
    /// Compliance mappings for the combined finding.
    #[serde(default)]
    pub compliance: Vec<String>,
}

fn default_severity() -> Severity {
    Severity::High
}

fn default_frequency() -> usize {
    2
}

/// A set of correlation rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationSet {
    /// Ruleset version.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Rules, evaluated in order.
    #[serde(default)]
    pub rules: Vec<CorrelationRule>,
}

fn default_version() -> u32 {
    1
}

impl CorrelationSet {
    /// The ruleset compiled into the binary.
    pub fn builtin() -> Self {
        serde_json::from_str(include_str!("../rules/correlation.json"))
            .expect("the embedded correlation ruleset must be valid JSON")
    }

    /// Loads a ruleset from a JSON file.
    pub fn from_path(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read correlation rules from {}", path.display()))?;
        let set: Self = serde_json::from_str(&text).with_context(|| {
            format!("failed to parse correlation rules from {}", path.display())
        })?;
        Ok(set)
    }

    /// Evaluates every rule against `findings`.
    pub fn evaluate(&self, findings: &[Finding]) -> Vec<Finding> {
        let mut correlated = Vec::new();

        for rule in &self.rules {
            let matches = findings
                .iter()
                .filter(|finding| finding.source != Source::Correlation)
                .filter(|finding| rule.matches(finding))
                .collect::<Vec<_>>();

            if matches.len() < rule.frequency.max(1) {
                continue;
            }
            if !rule
                .require_sources
                .iter()
                .all(|required| matches.iter().any(|finding| &finding.source == required))
            {
                continue;
            }
            let tags = matches
                .iter()
                .flat_map(|finding| finding.tags.iter().cloned())
                .collect::<BTreeSet<_>>();
            if !rule.require_tags.iter().all(|tag| tags.contains(tag)) {
                continue;
            }

            // Group by target when the rule is about one file or one control.
            let group = if rule.same_target {
                let mut targets: Vec<&str> = matches
                    .iter()
                    .map(|finding| finding.target.as_str())
                    .collect();
                targets.sort_unstable();
                targets.dedup();
                targets.iter().find_map(|target| {
                    let subset = matches
                        .iter()
                        .copied()
                        .filter(|finding| finding.target == *target)
                        .collect::<Vec<_>>();
                    (subset.len() >= rule.frequency.max(1)).then_some(subset)
                })
            } else {
                Some(matches)
            };

            let Some(group) = group else {
                continue;
            };

            let target = if rule.same_target {
                group
                    .first()
                    .map(|finding| finding.target.clone())
                    .unwrap_or_else(|| "scan".to_owned())
            } else {
                "scan".to_owned()
            };

            let mut related = group
                .iter()
                .map(|finding| format!("{} @ {}", finding.id, finding.target))
                .collect::<Vec<_>>();
            related.sort();
            related.dedup();
            let total_related = related.len();

            // A compound rule can legitimately cover dozens of findings. Keep
            // the evidence readable: list the first twelve and report the rest
            // as a count rather than a wall of identifiers.
            const MAX_LISTED: usize = 12;
            let listed = if related.len() > MAX_LISTED {
                let mut listed = related[..MAX_LISTED].to_vec();
                listed.push(format!("… and {} more", total_related - MAX_LISTED));
                listed
            } else {
                related.clone()
            };
            related.truncate(MAX_LISTED);

            let evidence = vec![
                Evidence::new("contributing findings", total_related.to_string()),
                Evidence::new("identifiers", listed.join(", ")),
            ];

            let findings_by_source = group
                .iter()
                .map(|finding| finding.source.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");

            let mut description = String::new();
            if !rule.description.is_empty() {
                description.push_str(&rule.description);
                description.push(' ');
            }
            description.push_str(&format!(
                "Built from {total_related} finding(s) across: {findings_by_source}."
            ));

            correlated.push(Finding {
                id: rule.id.clone(),
                title: rule.title.clone(),
                description,
                severity: rule.severity,
                level: rule.level_or_default(),
                source: Source::Correlation,
                target,
                category: Some("correlation".to_owned()),
                evidence,
                tags: vec!["correlated".to_owned()],
                mitre: rule.mitre.clone(),
                compliance: rule.compliance.clone(),
                remediation: rule.remediation.clone(),
                demo: group.iter().all(|finding| finding.demo),
                related,
            });
        }

        correlated
    }
}

impl CorrelationRule {
    fn level_or_default(&self) -> u8 {
        self.severity.level()
    }

    /// True when `finding` satisfies every selector on this rule.
    fn matches(&self, finding: &Finding) -> bool {
        if finding.level < self.min_level {
            return false;
        }
        if !self.sources.is_empty() && !self.sources.contains(&finding.source) {
            return false;
        }
        if !self.ids.is_empty()
            && !self
                .ids
                .iter()
                .any(|pattern| glob_match(pattern, &finding.id))
        {
            return false;
        }
        if !self.tags.is_empty() && !self.tags.iter().any(|tag| finding.tags.contains(tag)) {
            return false;
        }
        true
    }
}

/// Matches `value` against `pattern`, where a trailing `*` is a prefix wildcard.
fn glob_match(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

/// Convenience wrapper: evaluates the built-in ruleset.
pub fn correlate(findings: &[Finding]) -> Vec<Finding> {
    CorrelationSet::builtin().evaluate(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, severity: Severity, source: Source, target: &str, tag: &str) -> Finding {
        Finding::new(id, id, severity, source, target).with_tags(vec![tag.to_owned()])
    }

    #[test]
    fn prefix_globs_match() {
        assert!(glob_match("TVX-NAT-*", "TVX-NAT-001"));
        assert!(!glob_match("TVX-NAT-*", "TVX-YARA-001"));
        assert!(glob_match("SSH-7401", "SSH-7401"));
        assert!(!glob_match("SSH-7401", "SSH-7402"));
    }

    #[test]
    fn frequency_with_same_target_groups_findings() {
        let set = CorrelationSet {
            version: 1,
            rules: vec![CorrelationRule {
                id: "CORR-TEST".to_owned(),
                title: "Repeated high findings".to_owned(),
                description: String::new(),
                severity: Severity::High,
                sources: Vec::new(),
                ids: Vec::new(),
                tags: Vec::new(),
                min_level: 8,
                frequency: 2,
                same_target: true,
                require_sources: Vec::new(),
                require_tags: Vec::new(),
                remediation: None,
                mitre: Vec::new(),
                compliance: Vec::new(),
            }],
        };

        let findings = vec![
            finding("A", Severity::High, Source::Yara, "file", "x"),
            finding("B", Severity::High, Source::Native, "file", "x"),
            finding("C", Severity::High, Source::Native, "other", "x"),
        ];
        let correlated = set.evaluate(&findings);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].target, "file");
        assert_eq!(correlated[0].related.len(), 2);
        assert_eq!(correlated[0].source, Source::Correlation);
    }

    #[test]
    fn frequency_below_threshold_does_not_fire() {
        let set = CorrelationSet::builtin();
        let findings = vec![finding("A", Severity::Critical, Source::Yara, "file", "x")];
        assert!(set.evaluate(&findings).is_empty());
    }

    #[test]
    fn composite_rules_need_every_source() {
        let set = CorrelationSet {
            version: 1,
            rules: vec![CorrelationRule {
                id: "CORR-SOURCES".to_owned(),
                title: "Two engines agree".to_owned(),
                description: String::new(),
                severity: Severity::Critical,
                sources: Vec::new(),
                ids: Vec::new(),
                tags: Vec::new(),
                min_level: 1,
                frequency: 1,
                same_target: true,
                require_sources: vec![Source::Yara, Source::Audit],
                require_tags: Vec::new(),
                remediation: None,
                mitre: Vec::new(),
                compliance: Vec::new(),
            }],
        };
        let only_yara = vec![finding("A", Severity::High, Source::Yara, "f", "x")];
        assert!(set.evaluate(&only_yara).is_empty());

        let both = vec![
            finding("A", Severity::High, Source::Yara, "f", "x"),
            finding("B", Severity::High, Source::Audit, "f", "x"),
        ];
        assert_eq!(set.evaluate(&both).len(), 1);
    }

    #[test]
    fn builtin_ruleset_parses_and_is_documented() {
        let set = CorrelationSet::builtin();
        assert!(!set.rules.is_empty());
        for rule in &set.rules {
            assert!(!rule.title.is_empty());
            assert!(
                !rule.description.is_empty(),
                "{} needs a description",
                rule.id
            );
            assert!(rule.frequency >= 1);
        }
    }

    #[test]
    fn correlated_findings_do_not_recurse() {
        let mut findings = vec![
            finding("A", Severity::Critical, Source::Yara, "f", "x"),
            finding("B", Severity::Critical, Source::Native, "f", "x"),
            finding("C", Severity::Critical, Source::Native, "f", "x"),
        ];
        let isolated = correlate(&findings);
        assert!(!isolated.is_empty());
        findings.extend(isolated.clone());
        let again = correlate(&findings);
        assert!(
            again
                .iter()
                .all(|entry| entry.source == Source::Correlation),
            "correlation must never consume its own output"
        );
        // Adding correlated findings must not change the outcome.
        assert_eq!(again.len(), isolated.len());
        let mut ids = again
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>();
        let total = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "a rule must fire at most once");
    }
}
