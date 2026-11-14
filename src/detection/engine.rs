//! Detection engine abstraction.

use std::path::Path;

use anyhow::Result;

use crate::engine::RuleMatch;

/// A detection backend that checks one file and returns matching rules.
///
/// The scanner reads and hashes each file exactly once and hands the same
/// buffer to every engine, so implementations must not re-read the file.
/// Implementations must be safe to call from a scan worker thread and keep file
/// contents local.
pub trait DetectionEngine {
    /// Human-readable engine name, used in reports.
    fn name(&self) -> &'static str;

    /// Scans `content` from `path` and returns matches in a deterministic order.
    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<RuleMatch>>;
}
