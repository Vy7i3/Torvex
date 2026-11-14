//! Detection engines.
//!
//! Torvex runs two content engines and one host engine:
//!
//! * [`YaraEngine`] evaluates declarative YARA-X rules.
//! * [`NativeEngine`] runs the C++ Aho-Corasick indicator catalogue and the
//!   ELF/PE structural analyser.
//! * `crate::audit` runs the Python configuration assessment.
//!
//! All three are read-only and keep file contents local.

mod engine;
mod ffi;
mod native;
mod yara_engine;

pub use engine::DetectionEngine;
pub use native::{NativeEngine, NativeRule, RULES as NATIVE_RULES};
pub use yara_engine::YaraEngine;
