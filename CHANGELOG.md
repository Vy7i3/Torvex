# Changelog

All notable changes to Torvex are documented here. Torvex is experimental and
uses `0.x` versioning; breaking changes are expected between minor releases.

## 0.2.0 - 2026-11-13

### Added

- Per-entry scan failures. Directory scans now continue past unreadable files
  and report each failure with its path, stage (`walk`, `read`, or `detect`),
  and error message.
- Configurable YARA rule loading through `--rules`, `TORVEX_RULES_DIR`, a
  `rules/` directory next to the executable, or `./rules`, with compiled-in
  demo rules as the final fallback.
- Recursive discovery of `.yar` and `.yara` files, compiled in sorted order.
- Rule evidence in results: rule name, namespace, tags, description metadata,
  and a demo-fixture marker.
- Demo-rule detection and warnings in CLI, JSON stderr, and GUI output.
- Machine-readable `--json` scan output, including summary, results, rule
  provenance, duration, and failures.
- Documented exit codes: `0` clean, `1` findings, `2` incomplete or failed scan.
- Content-based MIME type detection for the first 8 KiB, with extension
  fallback.
- GUI scan-error panel, rule directory input, drag-and-drop support,
  Enter-to-scan, duration display, and copy-hash action.
- Unit tests for summary logic, fingerprints, formatting, embedded rules, and
  custom rule loading. Integration tests for JSON, exit codes, unreadable
  files, symlink policy, custom rules, and embedded fallback.
- `rules/README.md` with authoring, provenance, and licensing guidance.
- Tag-driven Linux release workflow and this changelog.

### Changed

- `scan_path` now returns a `ScanReport` containing results, failures, rule
  metadata, and skipped-entry counts instead of a plain result vector.
- Results expose `verdict` instead of `status`; `ScanFailure` and `ScanSummary`
  types were added.
- File hashing and type sniffing share one read of the file.
- The README now documents installation, rule resolution, JSON output, exit
  codes, limitations, privacy behavior, and support status.

### Removed

- The unused `malicious` verdict. Torvex only emits `clean` or `suspicious`
  until there is enough evidence to justify a stronger claim.
- The uncalibrated `confidence` field from CLI, GUI, and library results.

### Fixed

- Unreadable files no longer abort an entire directory scan.
- The GitHub workflow, ignore file, and Cargo configuration are now in the
  correct dot-directories (`.github/`, `.gitignore`, `.cargo/`).
- Rules are no longer resolved from the build machine's source path, which made
  installed binaries depend on a repository checkout.
- Non-regular directory entries are skipped explicitly instead of being treated
  as files.
- The GUI summary no longer displays a "Malicious: 0" counter for a verdict the
  engine never produces.

### Security

- Rule directories are treated as trusted input and documented as such.
- Each YARA file scan has a 30-second evaluation timeout.
- Explicit rule-directory errors are fatal instead of falling back to demo
  rules.

## 0.1.0

- Initial experimental alpha with CLI `scan`, `gui`, and `version` commands,
  recursive directory traversal, SHA-256 hashing, extension-based type
  estimates, YARA-X demo rules, and an `eframe` GUI.
