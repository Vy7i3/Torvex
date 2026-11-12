use anyhow::Result;
use std::path::Path;

use crate::engine::ScanResult;

pub trait DetectionEngine {
    fn scan_file(&self, path: &Path, sha256: &str, file_size: u64) -> Result<ScanResult>;
}
