//! YARA-X-backed detection engine.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use walkdir::WalkDir;
use yara_x::{Compiler, MetaValue, Rule, Rules, Scanner};

use crate::detection::DetectionEngine;
use crate::engine::{RuleMatch, RuleSetInfo};
use crate::findings::{Evidence, Severity, Source};

/// The demo rule set compiled into the binary as a portable fallback.
const EMBEDDED_RULES: &str = include_str!("../../rules/basic.yar");

/// Upper bound for one file's YARA evaluation. A pathological rule or file
/// should produce a reported failure instead of hanging the scan.
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);

/// A compiled YARA-X rule set and its provenance.
pub struct YaraEngine {
    rules: Rules,
    info: RuleSetInfo,
}

impl YaraEngine {
    /// Loads rules using this resolution order:
    ///
    /// 1. `rules_dir`, when provided.
    /// 2. The `TORVEX_RULES_DIR` environment variable, when set.
    /// 3. A `rules` directory next to the executable.
    /// 4. A `rules` directory in the current working directory.
    /// 5. The embedded demo fixtures, so an installed binary still works.
    ///
    /// An explicitly configured directory is never silently replaced by the
    /// embedded fallback. Compile errors and unreadable rule files are fatal.
    pub fn new(rules_dir: Option<&Path>) -> Result<Self> {
        if let Some(directory) = rules_dir {
            return Self::from_directory(directory);
        }

        if let Some(directory) = std::env::var_os("TORVEX_RULES_DIR") {
            return Self::from_directory(&PathBuf::from(directory));
        }

        for candidate in default_rule_candidates() {
            if candidate.is_dir()
                && let Some(engine) = Self::try_from_directory(&candidate)?
            {
                return Ok(engine);
            }
        }

        Self::from_embedded()
    }

    /// Metadata for the rule set that was loaded.
    pub fn info(&self) -> &RuleSetInfo {
        &self.info
    }

    /// Every compiled rule as `(identifier, namespace, is_demo)`, sorted.
    pub fn list_rules(&self) -> Vec<(String, String, bool)> {
        let mut rules = self
            .rules
            .iter()
            .map(|rule| {
                (
                    rule.identifier().to_owned(),
                    rule.namespace().to_owned(),
                    rule_is_demo(&rule),
                )
            })
            .collect::<Vec<_>>();
        rules.sort();
        rules
    }

    /// Loads rules from an explicit directory. Returns an error when the
    /// directory contains no YARA files.
    fn from_directory(directory: &Path) -> Result<Self> {
        Self::try_from_directory(directory)?.ok_or_else(|| {
            anyhow!(
                "no .yar or .yara rule files found in {}",
                directory.display()
            )
        })
    }

    /// Loads rules from `directory`, returning `Ok(None)` when the directory
    /// exists but contains no YARA files.
    fn try_from_directory(directory: &Path) -> Result<Option<Self>> {
        if !directory.exists() {
            bail!("rules directory {} does not exist", directory.display());
        }
        if !directory.is_dir() {
            bail!("rules path {} is not a directory", directory.display());
        }

        // WalkDir does not follow a symlink used as the root. Resolve an
        // explicitly configured symlinked rules directory once, while still
        // refusing to follow symlinks inside the tree.
        let walk_root = if fs::symlink_metadata(directory)?.file_type().is_symlink() {
            directory.canonicalize().with_context(|| {
                format!("failed to resolve rules directory {}", directory.display())
            })?
        } else {
            directory.to_path_buf()
        };

        let mut rule_files = Vec::new();
        for entry in WalkDir::new(&walk_root).follow_links(false) {
            let entry = entry.with_context(|| {
                format!(
                    "failed while reading rules directory {}",
                    directory.display()
                )
            })?;
            if entry.file_type().is_file() && has_rule_extension(entry.path()) {
                rule_files.push(entry.into_path());
            }
        }

        if rule_files.is_empty() {
            return Ok(None);
        }
        rule_files.sort();

        let mut compiler = Compiler::new();
        for path in &rule_files {
            let source = fs::read_to_string(path)
                .with_context(|| format!("failed to read YARA rules from {}", path.display()))?;
            compiler.add_source(source.as_str()).map_err(|error| {
                anyhow!(
                    "failed to compile YARA rules from {}: {error}",
                    path.display()
                )
            })?;
        }
        let rules = compiler.build();

        let info = rule_set_info(
            directory.display().to_string(),
            Some(directory.to_path_buf()),
            &rules,
        );
        Ok(Some(Self { rules, info }))
    }

    /// Compiles the fixtures embedded at build time.
    fn from_embedded() -> Result<Self> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(EMBEDDED_RULES)
            .map_err(|error| anyhow!("failed to compile embedded YARA demo rules: {error}"))?;
        let rules = compiler.build();
        let info = rule_set_info("embedded demo rules".to_owned(), None, &rules);
        Ok(Self { rules, info })
    }

    /// Convenience wrapper that reads `path` and scans it. The scanner uses
    /// [`DetectionEngine::scan`] instead so a file is read only once.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<RuleMatch>> {
        let content =
            fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        self.scan(path, &content)
    }
}

impl DetectionEngine for YaraEngine {
    fn name(&self) -> &'static str {
        "yara"
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<RuleMatch>> {
        let mut scanner = Scanner::new(&self.rules);
        scanner.set_timeout(SCAN_TIMEOUT);
        let results = scanner
            .scan(content)
            .with_context(|| format!("YARA scan failed for {}", path.display()))?;

        let mut matches = results
            .matching_rules()
            .map(|rule| {
                let demo = rule_is_demo(&rule);
                let severity = rule_severity(&rule);
                let identifier = rule.identifier().to_owned();
                RuleMatch {
                    engine: Source::Yara,
                    title: meta_string(&rule, "title").unwrap_or_else(|| identifier.clone()),
                    description: meta_string(&rule, "description"),
                    rule: identifier.clone(),
                    namespace: rule.namespace().to_owned(),
                    severity,
                    level: severity.level(),
                    tags: rule.tags().map(|tag| tag.identifier().to_owned()).collect(),
                    demo,
                    evidence: vec![Evidence::new("rule", identifier)],
                    mitre: meta_list(&rule, "mitre"),
                    compliance: meta_list(&rule, "compliance"),
                    remediation: meta_string(&rule, "remediation"),
                }
            })
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            right
                .level
                .cmp(&left.level)
                .then_with(|| (&left.rule, &left.namespace).cmp(&(&right.rule, &right.namespace)))
        });

        Ok(matches)
    }
}

fn default_rule_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        candidates.push(directory.join("rules"));
    }
    candidates.push(PathBuf::from("rules"));

    let mut unique = Vec::new();
    for candidate in candidates {
        if !unique.contains(&candidate) {
            unique.push(candidate);
        }
    }
    unique
}

fn has_rule_extension(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("yar") || extension.eq_ignore_ascii_case("yara")
    })
}

fn rule_set_info(source: String, rules_dir: Option<PathBuf>, rules: &Rules) -> RuleSetInfo {
    RuleSetInfo {
        source,
        rules_dir: rules_dir.map(|path| path.display().to_string()),
        rule_count: rules.iter().count(),
        demo_rule_count: rules.iter().filter(|rule| rule_is_demo(rule)).count(),
    }
}

fn meta_string(rule: &Rule<'_, '_>, key: &str) -> Option<String> {
    rule.metadata().find_map(|(name, value)| {
        if name == key
            && let MetaValue::String(text) = value
        {
            return Some(text.to_owned());
        }
        None
    })
}

/// Reads a comma- or semicolon-separated metadata list such as `mitre`.
///
/// Values may contain spaces ("PCI DSS 6.4"), so only explicit separators
/// split the list.
fn meta_list(rule: &Rule<'_, '_>, key: &str) -> Vec<String> {
    meta_string(rule, key)
        .map(|value| {
            value
                .split([',', ';'])
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn rule_is_demo(rule: &Rule<'_, '_>) -> bool {
    rule.metadata()
        .any(|(key, value)| key == "demo" && matches!(value, MetaValue::Bool(true)))
}

/// Severity from rule metadata, then tags, then a conservative default.
///
/// A demo fixture is never treated as more than low severity, whatever its
/// tags say, because demo rules exist only to exercise the scanner path.
fn rule_severity(rule: &Rule<'_, '_>) -> Severity {
    if rule_is_demo(rule) {
        return Severity::Low;
    }
    if let Some(severity) = meta_string(rule, "severity").and_then(|value| Severity::parse(&value))
    {
        return severity;
    }
    for tag in rule.tags() {
        match tag.identifier() {
            "critical" | "ransomware" | "webshell" => return Severity::Critical,
            "high" | "malware" | "loader" => return Severity::High,
            "medium" | "suspicious" => return Severity::Medium,
            "low" | "hunting" => return Severity::Low,
            _ => {}
        }
    }
    Severity::Medium
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_compile_and_are_labeled_demo() {
        let engine = YaraEngine::from_embedded().expect("compile embedded demo rules");
        assert_eq!(engine.info().rule_count, 3);
        assert_eq!(engine.info().demo_rule_count, 3);
        assert!(engine.info().is_demo_only());
        assert_eq!(engine.info().rules_dir, None);
    }

    #[test]
    fn loads_custom_rules_from_a_directory() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let rules_dir = temp.path().join("rules");
        fs::create_dir(&rules_dir).expect("create rules directory");
        fs::write(
            rules_dir.join("custom.yar"),
            r#"
rule torvex_test_custom
{
    meta:
        description = "Test-only custom marker"
        severity = "critical"
        mitre = "T1059, T1105"
    strings:
        $marker = "TORVEX_CUSTOM_TEST_MARKER"
    condition:
        $marker
}
"#,
        )
        .expect("write custom rule");
        let sample = temp.path().join("sample.txt");
        fs::write(&sample, "TORVEX_CUSTOM_TEST_MARKER").expect("write sample");

        let engine = YaraEngine::new(Some(&rules_dir)).expect("load custom rules");
        assert_eq!(engine.info().rule_count, 1);
        assert_eq!(engine.info().demo_rule_count, 0);

        let matches = engine.scan_file(&sample).expect("scan sample");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "torvex_test_custom");
        assert_eq!(matches[0].namespace, "default");
        assert!(!matches[0].demo);
        assert_eq!(matches[0].severity, Severity::Critical);
        assert_eq!(matches[0].level, 10);
        assert_eq!(matches[0].mitre, vec!["T1059", "T1105"]);
        assert_eq!(
            matches[0].description.as_deref(),
            Some("Test-only custom marker")
        );
    }

    #[cfg(unix)]
    #[test]
    fn loads_rules_through_a_symlinked_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("create temporary directory");
        let rules_dir = temp.path().join("real-rules");
        let rules_link = temp.path().join("linked-rules");
        fs::create_dir(&rules_dir).expect("create rules directory");
        fs::write(
            rules_dir.join("custom.yar"),
            "rule linked_rule { condition: true }",
        )
        .expect("write custom rule");
        symlink(&rules_dir, &rules_link).expect("create rules symlink");

        let engine = YaraEngine::new(Some(&rules_link)).expect("load linked rules");
        assert_eq!(engine.info().rule_count, 1);
    }

    #[test]
    fn rejects_an_empty_explicit_rules_directory() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let error = YaraEngine::new(Some(temp.path()))
            .err()
            .expect("empty rules directory should fail");
        assert!(error.to_string().contains("no .yar or .yara rule files"));
    }

    #[test]
    fn demo_rules_are_never_reported_above_low() {
        let engine = YaraEngine::from_embedded().expect("compile demo rules");
        let matches = engine
            .scan(Path::new("marker.txt"), b"TORVEX_YARA_EXAMPLE_TEXT")
            .expect("scan");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::Low);
        assert!(matches[0].demo);
    }

    #[test]
    fn scans_an_empty_buffer_without_panicking() {
        let engine = YaraEngine::from_embedded().expect("compile demo rules");
        let matches = engine.scan(Path::new("empty"), b"").expect("scan");
        assert!(matches.is_empty());
    }
}
