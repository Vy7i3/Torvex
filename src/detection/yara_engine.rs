use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use yara_x::{Compiler, Rules, Scanner};

use crate::detection::DetectionEngine;
use crate::engine::{ScanResult, Verdict};

pub struct YaraEngine {
    rules: Rules,
}

impl YaraEngine {
    pub fn new() -> Result<Self> {
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
        let mut compiler = Compiler::new();
        let mut loaded = false;

        for entry in fs::read_dir(&rules_dir)
            .with_context(|| format!("failed to read rules directory {}", rules_dir.display()))?
        {
            let path = entry?.path();
            let is_rule = path.extension().is_some_and(|extension| {
                extension.eq_ignore_ascii_case("yar") || extension.eq_ignore_ascii_case("yara")
            });
            if !path.is_file() || !is_rule {
                continue;
            }

            let source = fs::read_to_string(&path)
                .with_context(|| format!("failed to read YARA rules from {}", path.display()))?;
            compiler.add_source(source.as_str()).map_err(|error| {
                anyhow!(
                    "failed to compile YARA rules from {}: {error}",
                    path.display()
                )
            })?;
            loaded = true;
        }

        if !loaded {
            return Err(anyhow!("no YARA rules found in {}", rules_dir.display()));
        }

        let rules = compiler.build();
        Ok(Self { rules })
    }
}

impl DetectionEngine for YaraEngine {
    fn scan_file(&self, path: &Path, sha256: &str, file_size: u64) -> Result<ScanResult> {
        let mut scanner = Scanner::new(&self.rules);
        let matches = scanner
            .scan_file(path)
            .with_context(|| format!("YARA scan failed for {}", path.display()))?;

        let matching_rules = matches
            .matching_rules()
            .map(|rule| rule.identifier())
            .collect::<Vec<_>>();

        let (status, reason) = if matching_rules.is_empty() {
            (Verdict::Clean, None)
        } else {
            let names = matching_rules.join(", ");
            (
                Verdict::Suspicious,
                Some(format!("YARA rule match: {names}")),
            )
        };

        Ok(ScanResult {
            path: path.display().to_string(),
            sha256: sha256.to_string(),
            size: file_size,
            file_type: None,
            status,
            confidence: None,
            reason,
        })
    }
}
