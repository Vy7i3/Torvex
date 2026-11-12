# Torvex

Torvex is an early alpha of a local-first file scanner written in Rust. It
provides a command-line scanner and a small desktop GUI, calculates SHA-256
hashes, and checks files against YARA-X rules.

> **Alpha / experimental:** Torvex is not a complete antivirus and must not be
> used as the only protection for a computer. It has no maintained malware
> signature feed, real-time protection, quarantine, archive extraction, or
> calibrated detection score.

## What it does today

- Scan one file or walk a directory recursively.
- Calculate a SHA-256 hash and estimate the file type from its extension.
- Show matching YARA rule names as evidence.
- Report a rule match as **suspicious**, not confirmed malware. A YARA match by
  itself is not enough evidence to claim a file is malicious.
- Provide a CLI and an `eframe` desktop GUI. Scanning runs off the GUI thread.
- Keep file contents local; Torvex does not upload scanned files.

The rules in `rules/basic.yar` are harmless integration fixtures. They only
recognize Torvex demo markers and are not malware signatures. A clean result
means only that no loaded rule matched; it is not proof that a file is safe.
Confidence is shown as uncalibrated because Torvex does not yet have a labeled
evaluation corpus.

## Requirements

- Rust 1.95 or newer and Cargo.
- A graphical desktop session to use the GUI.
- An internet connection on the first build so Cargo can download dependencies.

YARA-X is written in Rust and avoids a separate system YARA installation. The
first full compile can take several minutes.

## Build and run

From the repository root:

```sh
cargo build
cargo run -- version
```

Scan a file or directory from the command line:

```sh
cargo run -- scan ./path/to/file-or-folder
```

Open the desktop GUI, enter a file or folder path, and select **Scan**:

```sh
cargo run -- gui
```

The current alpha loads YARA rules from the repository's `rules/` directory.
Run the built program while this source checkout and its rules directory are
available.

## Development checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The integration test uses temporary harmless files and checks the scanner and
CLI output. It does not download or require malware samples.

## Project direction

The next work is safer handling of unreadable files, configurable rule
directories, and a labeled evaluation corpus that measures false positives and
false negatives. Detection features will remain explainable and confidence
scores will only be added after calibration against that corpus. Any third-party
rules or signature feeds will need provenance and license review before use.

## License

Torvex is available under either the MIT License or Apache License, Version 2.0,
at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). Third-party dependencies and future rule sets
may have separate licenses.
