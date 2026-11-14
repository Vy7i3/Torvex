//! Safe wrapper around the C++ indicator core.
//!
//! This is the only module in the crate allowed to contain `unsafe` code; the
//! crate root uses `#![deny(unsafe_code)]` and this module opts in explicitly.
//! Everything below exists to make three guarantees:
//!
//! 1. The opaque matcher pointer is owned by [`NativeMatcher`] and destroyed
//!    exactly once.
//! 2. Strings returned by the native layer are copied into Rust and freed with
//!    the allocator that produced them, even when conversion fails.
//! 3. No slice outlives the call that borrows it.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr::NonNull;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Opaque C++ matcher.
#[repr(C)]
struct TvMatcher {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn tv_matcher_create() -> *mut TvMatcher;
    fn tv_matcher_add_rule(
        matcher: *mut TvMatcher,
        rule_id: *const c_char,
        require_all: c_int,
        needles: *const *const c_char,
        lengths: *const usize,
        nocase: *const c_int,
        needle_count: usize,
    ) -> c_int;
    fn tv_matcher_build(matcher: *mut TvMatcher) -> c_int;
    fn tv_matcher_rule_count(matcher: *const TvMatcher) -> usize;
    fn tv_scan(matcher: *const TvMatcher, data: *const u8, len: usize) -> *mut c_char;
    fn tv_core_version() -> *const c_char;
    fn tv_free(value: *mut c_char);
    fn tv_matcher_destroy(matcher: *mut TvMatcher);
}

/// One needle and its case-sensitivity.
#[derive(Debug, Clone, Copy)]
pub struct Needle {
    /// Literal byte sequence to find.
    pub pattern: &'static str,
    /// Match ASCII case-insensitively.
    pub nocase: bool,
}

/// A rule compiled into the native matcher.
#[derive(Debug, Clone, Copy)]
pub struct MatcherRule {
    /// Stable identifier reported back by the scanner.
    pub id: &'static str,
    /// Require every needle to match somewhere in the file.
    pub require_all: bool,
    /// Alternative-free needle list.
    pub needles: &'static [Needle],
}

/// A rule that fired in the native scan.
#[derive(Debug, Clone, Deserialize)]
pub struct NativeHit {
    /// Rule identifier.
    pub id: String,
    /// Number of needle matches.
    pub hits: usize,
    /// Offset just past the first match.
    pub first_offset: usize,
}

/// A structural observation from the ELF/PE analyser.
#[derive(Debug, Clone, Deserialize)]
pub struct NativeStructural {
    /// Indicator identifier.
    pub id: String,
    /// Human-readable explanation.
    pub detail: String,
}

/// An indicator extracted from the content.
#[derive(Debug, Clone, Deserialize)]
pub struct NativeIoc {
    /// `url`, `email` or `ipv4`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Extracted value.
    pub value: String,
    /// Byte offset.
    pub offset: usize,
}

/// The full native analysis document.
#[derive(Debug, Clone, Deserialize)]
pub struct NativeScan {
    /// Native document version.
    #[allow(dead_code)]
    pub version: u32,
    /// Bytes analysed.
    #[allow(dead_code)]
    pub size: usize,
    /// Container kind.
    pub kind: String,
    /// Architecture, when known.
    pub arch: String,
    /// Word size in bits.
    pub bits: u8,
    /// Whole-buffer Shannon entropy.
    pub entropy: f64,
    /// Worst 4 KiB window entropy.
    pub max_window_entropy: f64,
    /// Longest base64-alphabet run.
    pub longest_base64_run: usize,
    /// Rules that fired.
    pub rules: Vec<NativeHit>,
    /// Structural indicators.
    pub structural: Vec<NativeStructural>,
    /// Extracted indicators.
    pub iocs: Vec<NativeIoc>,
}

/// Owns a compiled native matcher.
pub struct NativeMatcher {
    handle: NonNull<TvMatcher>,
    rule_count: usize,
}

/// Owns a raw handle during construction so early returns still destroy it.
struct HandleGuard(NonNull<TvMatcher>);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe { tv_matcher_destroy(self.0.as_ptr()) };
    }
}

impl NativeMatcher {
    /// Compiles `rules` into a fresh automaton.
    pub fn new(rules: &[MatcherRule]) -> Result<Self> {
        let handle = unsafe { tv_matcher_create() };
        let guard = HandleGuard(
            NonNull::new(handle)
                .context("the native core could not allocate a matcher (out of memory)")?,
        );
        let handle = guard.0;

        for rule in rules {
            let id = CString::new(rule.id)
                .with_context(|| format!("native rule id {:?} contains a NUL byte", rule.id))?;
            let mut owned = Vec::with_capacity(rule.needles.len());
            for needle in rule.needles {
                owned.push(CString::new(needle.pattern).with_context(|| {
                    format!(
                        "native rule {:?} has a needle containing a NUL byte",
                        rule.id
                    )
                })?);
            }

            let pointers = owned.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let lengths = rule
                .needles
                .iter()
                .map(|needle| needle.pattern.len())
                .collect::<Vec<_>>();
            let nocase = rule
                .needles
                .iter()
                .map(|needle| if needle.nocase { 1 } else { 0 })
                .collect::<Vec<_>>();

            let status = unsafe {
                tv_matcher_add_rule(
                    handle.as_ptr(),
                    id.as_ptr(),
                    if rule.require_all { 1 } else { 0 },
                    pointers.as_ptr(),
                    lengths.as_ptr(),
                    nocase.as_ptr(),
                    pointers.len(),
                )
            };
            if status != 0 {
                bail!(
                    "native core rejected rule {:?} (status {status}); check for empty needles",
                    rule.id
                );
            }
        }

        let status = unsafe { tv_matcher_build(handle.as_ptr()) };
        if status != 0 {
            bail!("native core failed to build the matcher (status {status})");
        }
        let rule_count = unsafe { tv_matcher_rule_count(handle.as_ptr()) };

        // Ownership moves into the returned value; the guard must not run.
        std::mem::forget(guard);
        Ok(Self { handle, rule_count })
    }

    /// Number of registered rules, as counted by the C++ side.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Scans a byte slice in one pass.
    pub fn scan(&self, data: &[u8]) -> Result<NativeScan> {
        // An empty slice may carry a null pointer, which the C ABI rejects.
        let placeholder = [0_u8];
        let (pointer, length) = if data.is_empty() {
            (placeholder.as_ptr(), 0)
        } else {
            (data.as_ptr(), data.len())
        };

        let raw = unsafe { tv_scan(self.handle.as_ptr(), pointer, length) };
        if raw.is_null() {
            bail!("native core could not scan the buffer");
        }

        // `raw` must be freed with the C allocator even if UTF-8 conversion
        // fails, so take ownership before doing anything fallible.
        struct Owned(*mut c_char);
        impl Drop for Owned {
            fn drop(&mut self) {
                unsafe { tv_free(self.0) };
            }
        }
        let owned = Owned(raw);

        let text = unsafe { CStr::from_ptr(owned.0) }
            .to_str()
            .context("native core returned invalid UTF-8")?;
        serde_json::from_str(text).context("native core returned malformed JSON")
    }
}

// The matcher is immutable after `build`, and `tv_scan` only reads it, so the
// handle can be shared across threads. Mutation is impossible through the
// public API.
unsafe impl Send for NativeMatcher {}
unsafe impl Sync for NativeMatcher {}

impl Drop for NativeMatcher {
    fn drop(&mut self) {
        unsafe { tv_matcher_destroy(self.handle.as_ptr()) };
    }
}

impl std::fmt::Debug for NativeMatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeMatcher")
            .field("rules", &self.rule_count)
            .finish()
    }
}

/// Version string reported by the C++ core.
pub fn core_version() -> String {
    let pointer = unsafe { tv_core_version() };
    if pointer.is_null() {
        return "unknown".to_owned();
    }
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEEDLES: &[Needle] = &[Needle {
        pattern: "needle",
        nocase: false,
    }];

    #[test]
    fn compiles_and_scans_through_the_abi() {
        let matcher = NativeMatcher::new(&[MatcherRule {
            id: "TEST-001",
            require_all: false,
            needles: NEEDLES,
        }])
        .expect("compile matcher");
        assert_eq!(matcher.rule_count(), 1);

        let result = matcher.scan(b"a needle in a haystack").expect("scan");
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].id, "TEST-001");
        assert_eq!(result.kind, "unknown");
    }

    #[test]
    fn reports_a_library_version() {
        assert!(core_version().contains("torvex-native"));
    }

    #[test]
    fn rejects_a_rule_with_no_needles() {
        let error = NativeMatcher::new(&[MatcherRule {
            id: "TEST-EMPTY",
            require_all: false,
            needles: &[],
        }])
        .expect_err("empty needle list must fail");
        assert!(error.to_string().contains("rejected rule"));
    }

    #[test]
    fn empty_input_is_safe() {
        let matcher = NativeMatcher::new(&[MatcherRule {
            id: "TEST-001",
            require_all: false,
            needles: NEEDLES,
        }])
        .expect("compile matcher");
        let result = matcher.scan(b"").expect("scan empty");
        assert_eq!(result.size, 0);
        assert!(result.rules.is_empty());
    }
}
