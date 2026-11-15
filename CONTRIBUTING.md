# Contributing to Torvex

Torvex is experimental software. Small, reviewable changes with tests and
honest documentation are welcome.

## Before opening a pull request

Run these checks from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
python3 -m unittest discover -s python -v

g++ -std=c++17 -O2 native/torvex_core.cpp native/test_native.cpp -o /tmp/torvex-native
/tmp/torvex-native

cargo check --locked --features gui   # only if you touched the GUI
```

`cargo test --all-targets` builds the C++ core through `build.rs`, so a C++17
compiler must be installed. The standalone native harness is still worth running
when you change `native/`: it exercises the ABI without Cargo.

If you change the CLI, GUI, JSON schema, report format, rule loading, exit
codes, scoring or supported platforms, update the README and CHANGELOG in the
same pull request. Add or update tests for behavior changes. Keep unrelated
formatting or dependency churn out of focused pull requests.

## Safety rules for contributions

Use synthetic, harmless files in tests. Do not add malware samples, exploit
payloads, private user files, credentials, or real customer data to the
repository.

Do not present a rule match as confirmed malware. Severity is a triage hint, not
a detection probability. Do not add calibrated-sounding confidence scores
without a labeled evaluation corpus and documented measurements.

Scanned content must stay read-only: no quarantine, deletion or repair paths.
Audit controls must not modify host configuration. External commands need a
read-only allowlist entry.

The GUI is behind the `gui` feature. If you change it, include a manual test note
describing the desktop session (Wayland or X11), the path scanned, and what you
observed. If you cannot test the GUI visually, say so explicitly.

## Detection rules

Rule changes should include:

- a harmless regression fixture;
- at least one nearby non-matching fixture;
- a clear explanation of the evidence the rule matches;
- the rule author, license, and source/reference metadata;
- `demo = true` for harmless fixtures, and no demo flag for detection content.

Read [rules/README.md](rules/README.md) before adding rules. Broad or unverified
matches must not be presented as confirmed malware. Third-party rule sets need a
separate license and provenance review before inclusion.

Native indicators live in `src/detection/native.rs`; structural checks are split
between the C++ analyser and the `STRUCTURAL` policy table, and the ids must
match. Audit controls live in `python/torvex_audit.py` and must be testable
against a fake root.

## Reporting a security issue

Do not put vulnerability details or malware samples in a public issue. See
[SECURITY.md](SECURITY.md) for reporting guidance.
