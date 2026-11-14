# Changelog

All notable changes to Torvex are documented here. Torvex is experimental and
uses `0.x` versioning; breaking changes are expected between minor releases.

## 0.3.0 - 2026-11-14

The "three engines, one report" release. Torvex now answers both "what is in
these files?" and "how is this host configured?", and correlates the answers.

### Added

- **Native C++ indicator engine** (`native/torvex_core.cpp`, built by
  `build.rs` with the `cc` crate). One Aho-Corasick automaton per case mode
  scans a file in a single pass. 33 content indicators cover script loaders,
  reverse shells, credential access, persistence, miners, web shells, ransomware
  notes, C2/exfiltration and defense evasion, each with severity, tags, ATT&CK
  mapping and remediation.
- **ELF/PE structural analysis**: W^X segments, writable entry points,
  executable stacks, missing RELRO, non-PIE, RWX sections, ASLR/NX/CFG flags,
  stripped relocations, packer section names and high-entropy sections.
- **Entropy and IOC extraction**: whole-buffer and worst-window entropy, longest
  base64 run, URLs, e-mail addresses and IPv4 literals.
- **Python host audit engine** (`python/torvex_audit.py`, embedded in the
  binary): 57 Lynis-style controls across ACCT, AUTH, SSH, FIRE, KRNL, FILE,
  LOGG, PKGS, SERV, SCHD, CRYP and MAND, with stable ids, rationale,
  remediation, compliance and ATT&CK mappings.
- **Hardening index** with category weights, 60% credit for suggestions and
  inapplicable-control exclusion. A root without `/etc` skips every control.
- **JSON audit policies** (`--policy`) with category weights, disabled controls,
  severity overrides and a minimum score.
- **Audit plugins** (`torvex_audit.py --plugin file.py`) that can register extra
  controls.
- **Correlation engine** (`src/correlation.rs`, `rules/correlation.json`)
  modelled on Wazuh: id selection with prefix wildcards, `frequency`,
  `same_target`, `require_sources` and `require_tags`, producing compound
  findings with a `related` list.
- **Unified finding model** with severity, Wazuh-style level, source, tags,
  ATT&CK, compliance, evidence, remediation and demo marking.
- **Risk score** (0-100) and severity buckets in the report summary.
- **Self-contained HTML dashboard** with filtering, search, sorting, expandable
  findings, audit scorecards, JSON export and print support. No external assets.
- **Local web dashboard** (`torvex serve`) with a scan form, token-protected
  mutations, root confinement and a restrictive CSP.
- **New YARA packs**: `suspicious_scripts.yar`, `webshells.yar`, `iocs.yar`
  (17 rules total, 14 detection + 3 demo) with `severity`, `mitre`, `compliance` and `remediation`
  metadata.
- **New commands**: `audit`, `report`, `serve`, `rules list`, `rules validate`,
  `info`.
- **`--fail-on`** thresholds, per-command formats (`pretty`, `json`, `html`) and
  `--output` for every format.
- **Vendor-directory skipping** (`.git`, `node_modules`, `target`, ...) with
  `--include-vendor` to disable it.
- **Native test harness** (`native/test_native.cpp`, 50 assertions) independent
  of Cargo.
- **Python unittest suite** (30 tests) using insecure and hardened fake roots.
- **Architecture documentation** comparing the framework with Lynis and Wazuh.

### Changed

- `ScanOptions` gained engine selection, audit options, correlation options, a
  scan-size cap and an ignore list. Use `..ScanOptions::default()`.
- `ScanReport` is now the serialisable report itself (schema
  `torvex.report.v2`); the CLI no longer wraps it in a separate struct.
- `RuleMatch` gained engine, title, severity, level, evidence, ATT&CK,
  compliance and remediation fields; matches are sorted most severe first.
- `DetectionEngine` now takes a buffer (`scan(path, content)`) so a file is read
  only once for hashing and detection.
- Fingerprinting returns buffered content and a truncation flag alongside the
  hash, size and type.
- The desktop GUI is an opt-in `gui` feature. The default build is headless.
- Human output was redesigned around risk, findings and host hardening.
- `--json` remains an alias for `--format json`.
- The CI workflow installs a C++ toolchain, runs Clippy, rustfmt, Rust tests,
  Python tests and the native harness, and checks the GUI feature separately.

### Fixed

- YARA rule severity no longer defaults to "suspicious"; rules can declare
  `severity` and demo fixtures are capped at low.
- Demo fixtures no longer contribute to the risk score.
- Audit controls whose subject is absent (no sshd, no auditd) are skipped rather
  than counted as passing.
- Audit roots that do not exist are rejected with a clear error instead of
  producing an empty report.
- The audit engine no longer hangs: it has a hard timeout and captures output
  through files rather than pipes.
- Path traversal outside an audit root is refused.
- HTML reports escape embedded JSON so a hostile file name cannot break out of
  the script element.

### Security

- `unsafe` remains denied crate-wide and is confined to `detection::ffi`, with
  ownership and allocator rules documented and tested.
- The native core caps matches, IOCs, needles and scanned bytes; the audit has a
  120-second timeout; YARA keeps its 30-second per-file timeout.
- The web dashboard binds loopback, requires a per-process token for scans,
  confines scans to `--root`, caps request sizes and sends `no-store`,
  `nosniff`, `DENY` and a restrictive CSP.
- Audit commands run from a read-only allowlist, and only against the live root.
- Scanned files are never modified, quarantined or deleted.

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
