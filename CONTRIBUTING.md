# Contributing to Torvex

Torvex is an experimental alpha. Small, reviewable changes with tests are
welcome.

## Before opening a pull request

Run these checks from the repository root:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Use synthetic, harmless files in tests. Do not add malware samples, exploit
payloads, private user files, or real credentials to the repository.

## Detection rules

Rule changes should include a harmless regression fixture, a clear explanation
of the evidence the rule matches, and the rule's source and license. Broad or
unverified matches must not be presented as confirmed malware. Third-party rule
sets need a separate license and provenance review before inclusion.

## Reporting a security issue

Do not put vulnerability details or malware samples in a public issue. See
[SECURITY.md](SECURITY.md) for reporting guidance.
