use anyhow::{Context, Result};
use std::path::Path;
use walkdir::WalkDir;

use crate::detection::{DetectionEngine, YaraEngine};
use crate::engine::ScanResult;
use crate::utils::calculate_sha256;

pub fn scan_path(path: &Path) -> Result<Vec<ScanResult>> {
    let engine = YaraEngine::new()?;
    let mut results = Vec::new();

    for entry in WalkDir::new(path) {
        let entry = entry.with_context(|| format!("failed while walking {}", path.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }

        let file_path = entry.path();
        let sha256 = calculate_sha256(file_path)
            .with_context(|| format!("failed to hash {}", file_path.display()))?;
        let file_size = entry
            .metadata()
            .with_context(|| format!("failed to read metadata for {}", file_path.display()))?
            .len();
        let mut result = engine.scan_file(file_path, &sha256, file_size)?;
        result.file_type = mime_guess::from_path(file_path)
            .first()
            .map(|mime| mime.to_string());
        results.push(result);
    }

    Ok(results)
}
