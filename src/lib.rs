//! Torvex is a local-first security scanner.
//!
//! Three engines feed one report:
//!
//! * **YARA-X** evaluates declarative content rules.
//! * A **C++ native core** ([`detection::NativeEngine`]) runs a single-pass
//!   Aho-Corasick indicator catalogue and structural analysis of ELF and PE
//!   images.
//! * A **Python audit engine** ([`audit`]) performs a Lynis-style, read-only
//!   configuration assessment of a Linux host and computes a hardening index.
//!
//! Findings share one model ([`findings::Finding`]) with severity, a
//! Wazuh-style numeric level, ATT&CK mappings and remediation. [`correlation`]
//! then applies Wazuh-style composite rules so that three weak signals become
//! one strong one.
//!
//! Local-first: file contents are read locally and never uploaded. Torvex makes
//! no network requests of its own.
//!
//! Safety policy: `unsafe` is denied crate-wide and allowed only in
//! `detection::ffi`, which implements the C ABI boundary. The scanner itself
//! never writes to, deletes or quarantines a scanned file.
//!
//! This is not an antivirus. A rule match is evidence to review, not proof of
//! malware, and a clean result only means that no loaded rule matched.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod correlation;
pub mod detection;
pub mod engine;
pub mod findings;
pub mod report;
pub mod scanner;
pub mod utils;
pub mod web;

#[cfg(feature = "gui")]
pub mod gui;
