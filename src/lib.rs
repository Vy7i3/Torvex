//! Torvex is an experimental, local-first file scanner.
//!
//! The library exposes path scanning, YARA-X detection, and shared result
//! types. File contents are read locally and are never uploaded by this crate.
//!
//! This is not an antivirus: demo rules in the repository are harmless test
//! fixtures, and a clean result only means that no loaded rule matched.

#![forbid(unsafe_code)]

pub mod detection;
pub mod engine;
pub mod gui;
pub mod scanner;
pub mod utils;
