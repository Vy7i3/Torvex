# Contributing to Torvex

Torvex is an experimental alpha. Small, reviewable changes with tests and
honest documentation are welcome.

## Before opening a pull request

Run these checks from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

If you change the CLI, GUI, JSON schema, rule loading, exit codes, or supported
platforms, update the README and CHANGELOG in the same pull request. Add or
update tests for behavior changes. Keep unrelated formatting or dependency
churn out of focused pull requests.

## Safety rules for contributions

Use synthetic, harmless files in tests. Do not add malware samples, exploit
payloads, private user files, credentials, or real customer data to the
repository.

Do not present a rule match as confirmed malware. Torvex currently reports
matches as **suspicious** evidence. Do not add confidence scores or detection
claims without a labeled evaluation corpus and documented measurements.

The GUI compiles in CI. If you change it, include a manual test note describing
the desktop session (Wayland or X11), the path scanned, and what you observed.
If you cannot test the GUI visually, say so explicitly.

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

## Reporting a security issue

Do not put vulnerability details or malware samples in a public issue. See
[SECURITY.md](SECURITY.md) for reporting guidance.
