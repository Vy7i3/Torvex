//! Detection engine abstraction.

use std::path::Path;

use anyhow::Result;

use crate::engine::RuleMatch;

/// A detection backend that checks one file and returns matching rules.
///
/// Implementations must be safe to call from a scan worker thread and should
/// keep file contents local.
pub trait DetectionEngine {
    /// Scans `path` and returns matching rules, sorted deterministically.
    fn scan_file(&self, path: &Path) -> Result<Vec<RuleMatch>>;
}
