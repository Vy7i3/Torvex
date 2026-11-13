# Torvex

![Status: experimental alpha](https://img.shields.io/badge/status-experimental%20alpha-orange)
![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![Rust: 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange)

Torvex is an experimental, local-first file scanner written in Rust. It provides
a command-line interface and a small desktop GUI, calculates SHA-256 hashes,
estimates file types, and checks files against [YARA-X](https://github.com/VirusTotal/yara-x)
rules.

> **Alpha / experimental:** Torvex is not an antivirus and must not be used as
> the only protection for a computer. It has no maintained malware-signature
> feed, real-time protection, quarantine, remediation, archive extraction, or
> calibrated detection score. A rule match is reported as **suspicious**, not
> confirmed malware, and a clean result only means that no loaded rule matched.

Version 0.2.0 is the current development release. The project follows `0.x`
versioning, so command-line output and library APIs may change between releases.

## What Torvex does today

- Scan one file or recursively walk a directory.
- Continue a directory scan when individual files or directories cannot be read,
  and report each failure with its path, stage, and error.
- Calculate a SHA-256 hash from the bytes that were read.
- Estimate the MIME type from the first 8 KiB of content, falling back to the
  file extension.
- Check files with YARA-X and report the matching rule name, namespace, tags,
  and `description` metadata as evidence.
- Distinguish harmless demo fixtures from other rules and warn when demo rules
  are active.
- Load rules from a configurable directory, with a built-in demo fallback so an
  installed binary still runs.
- Provide human-readable output or a machine-readable JSON report.
- Use documented exit codes suitable for scripts.
- Run scans off the GUI thread. The GUI supports drag-and-drop, reports scan
  errors, and copies hashes to the clipboard.
- Keep scanned file contents local. Torvex makes no network requests and does
  not upload files.
- Forbid `unsafe` code in Torvex's own crate with `#![forbid(unsafe_code)]`.

Torvex does not:

- provide real-time or background protection;
- quarantine, delete, or repair files;
- extract archives before scanning;
- maintain a malware-signature feed or reputation service;
- detect malware by heuristics, emulation, or machine learning;
- follow symlinks found inside a directory tree;
- claim that a clean scan proves a file is safe.

## Requirements

- Rust 1.95 or newer and Cargo.
- Linux is the tested platform (Wayland and X11 builds are enabled). macOS and
  Windows may compile, but are not currently tested or supported.
- A graphical desktop session to use the GUI.
- Network access on the first build so Cargo can download dependencies.

YARA-X is written in Rust, so no separate system YARA installation is needed.
The first full compile can take several minutes.

### Linux build dependencies

On Ubuntu/Debian, the CI configuration uses:

```sh
sudo apt-get install --yes \
  build-essential \
  pkg-config \
  libgl1-mesa-dev \
  libwayland-dev \
  libx11-dev \
  libxcb-render0-dev \
  libxcb-shape0-dev \
  libxcb-xfixes0-dev \
  libxkbcommon-dev
```

On Arch-based systems the equivalent packages are typically:

```sh
sudo pacman -S --needed base-devel pkgconf mesa wayland libx11 libxcb libxkbcommon
```

Package names vary by distribution. If the GUI dependencies are unavailable,
the CLI-only build still requires the graphics libraries because the GUI is
compiled into the same binary.

## Build and run

From the repository root:

```sh
cargo build
cargo run -- version
```

Scan a file or directory:

```sh
cargo run -- scan ./path/to/file-or-folder
cargo run -- scan ./path/to/file-or-folder --json
```

Open the desktop GUI:

```sh
cargo run -- gui
```

Install the binary into Cargo's binary directory:

```sh
cargo install --path .
torvex --help
```

The installed binary works without a repository checkout because the demo rules
are compiled in. To use external rules, see [Rule loading](#rule-loading).

### Prebuilt Linux archive

Tagged GitHub releases attach a `torvex-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
archive containing the `torvex` binary, the bundled demo rules, and the main
documentation, plus a `.sha256` checksum file. The archive is built on Ubuntu
24.04; check compatibility if you use an older distribution.

```sh
tar -xzf torvex-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
cd torvex
./torvex scan ./path/to/file-or-folder
```

Prebuilt archives are not code-signed.

## Command-line usage

```text
torvex [--rules DIR] scan <PATH> [--json]
torvex [--rules DIR] gui
torvex version
```

### Scan a path

```sh
torvex scan ~/Downloads
torvex scan ./one-file.bin
torvex scan ./samples --json > report.json
```

Human-readable output includes a scan summary, findings with hashes and rule
evidence, and a separate list of entries that could not be read. JSON output is
written to stdout as a single object; warnings go to stderr so stdout remains
valid JSON.

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed and no loaded rule matched. |
| `1` | Scan completed and at least one file matched a rule. |
| `2` | The scan was incomplete, could not start, or arguments/rules were invalid. |

A scan with unreadable files exits with `2`, even if it also found a match,
because some files were not checked. Review the `failures` array in JSON output
or the `Scan errors` section in human output.

### JSON report

The JSON schema may evolve between minor releases while Torvex remains `0.x`.
Top-level fields are:

```json
{
  "tool": "torvex",
  "version": "0.2.0",
  "root": "/path/to/scan",
  "rules": {
    "source": "/path/to/rules",
    "rules_dir": "/path/to/rules",
    "rule_count": 3,
    "demo_rule_count": 3
  },
  "summary": {
    "scanned": 2,
    "clean": 1,
    "suspicious": 1,
    "errors": 0,
    "skipped": 0,
    "bytes_scanned": 46
  },
  "duration_ms": 42,
  "results": [
    {
      "path": "/path/to/scan/marker.txt",
      "sha256": "b5e3a4a8abee79233d8a661f31d6cc617249e5d4157b4538c74815df24226788",
      "size": 24,
      "file_type": "text/plain",
      "verdict": "suspicious",
      "matches": [
        {
          "rule": "torvex_example_text",
          "namespace": "default",
          "tags": ["demo", "harmless"],
          "description": "Matches a harmless Torvex example text marker",
          "demo": true
        }
      ]
    }
  ],
  "failures": []
}
```

- `results` contains only files that were successfully read and scanned.
- `failures` contains entries that could not be walked, read, or scanned, with
  `kind` set to `walk`, `read`, or `detect`.
- `skipped` counts non-regular entries such as symlinks and special files found
  during directory traversal.

## Rule loading

Torvex resolves its YARA rule set in this order:

1. The `--rules DIR` command-line option.
2. The `TORVEX_RULES_DIR` environment variable.
3. A `rules` directory next to the executable.
4. A `rules` directory in the current working directory.
5. The demo fixtures compiled into the binary.

Rule directories are searched recursively for `.yar` and `.yara` files. Files
are compiled in sorted path order. An explicitly selected directory must exist,
be readable, and contain at least one valid YARA file; otherwise the scan fails
instead of silently falling back. Empty directories found during automatic
discovery are ignored so discovery can continue, but unreadable rule files and
compilation errors are always fatal. A symlink used as the rules directory is
resolved once; symlinks inside the tree are not followed.

Examples:

```sh
torvex scan ./samples --rules ./rules
TORVEX_RULES_DIR=/opt/torvex/rules torvex scan ./samples
torvex gui --rules ./rules
```

> **Treat rule directories as trusted input.** YARA rules can use modules and
> conditions that consume CPU or memory, and third-party rules may have their
> own licenses and provenance. Only load rule sets you trust. Rule compilation
> and evaluation happen locally; Torvex does not fetch rules.

The repository's `rules/basic.yar` contains harmless fixtures for testing the
integration. Every fixture sets `demo = true` in its metadata and uses the
`demo`/`harmless` tags. Torvex counts these rules, labels matching findings as
demo fixtures, and prints a warning. They do not detect malware. See
[rules/README.md](rules/README.md) before adding or sharing rules.

## GUI

Run:

```sh
torvex gui
```

The GUI accepts a file or folder path, an optional rules directory, and a
`Scan` button. You can also:

- drag and drop a file or folder onto the window;
- press Enter in the path field to start a scan;
- use the current working directory as the target;
- choose whether clean files are listed;
- review unreadable entries in a dedicated scan-errors panel;
- copy a file's SHA-256 hash.

The GUI does not yet support cancelling a running scan. Large directory scans
continue until they finish or the window is closed.

A manual Wayland smoke test has covered the initial layout, scan results, clean
file filtering, scan-error display, and basic keyboard navigation. X11 and other
desktop environments still need a manual pass; the GUI compiles in CI but does
not have an automated visual test yet.

## Development checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

The test suite uses temporary harmless files only. It covers clean and matching
scans, content-based type detection, custom and embedded rules, JSON output,
exit codes, missing paths, unreadable files and directories on Unix, and symlink
traversal policy. It does not download or require malware samples.

CI is defined in [.github/workflows/ci.yml](.github/workflows/ci.yml). It runs
formatting, Clippy, and tests on stable Rust, and checks all targets on the
declared minimum of Rust 1.95.0. A separate tag-driven workflow builds and
attaches a Linux release archive; see
[.github/workflows/release.yml](.github/workflows/release.yml).

## Project layout

```text
src/main.rs                  CLI parsing, output, exit codes
src/gui.rs                   eframe desktop interface
src/scanner/mod.rs           file and directory traversal
src/detection/engine.rs      detection engine trait
src/detection/yara_engine.rs rule loading, YARA-X scanning, evidence
src/engine/mod.rs            scan result, failure, summary, and verdict types
src/utils/mod.rs             hashing, type detection, formatting
rules/basic.yar              harmless demo fixtures
rules/README.md              rule authoring and provenance guidance
tests/integration_test.rs    CLI and scanner integration coverage
.github/workflows/ci.yml     formatting, lint, and test checks
.github/workflows/release.yml tag-driven Linux release build
```

## Detection model and limitations

Torvex's current verdict is deliberately simple:

- **Clean:** no loaded rule matched. This is not a safety guarantee.
- **Suspicious:** at least one loaded rule matched. This is evidence to review,
  not a malware determination.

There is no confidence score. Earlier alpha output displayed an uncalibrated
"confidence" field; it has been removed until a labeled corpus can justify a
meaningful score. Any future score will need documented false-positive and
false-negative measurements.

Current limitations include:

- only YARA-X rule matching, with a 30-second evaluation timeout per file;
- no maximum file size: every selected file is read fully to calculate its hash,
  so very large files take time;
- all results are kept in memory, so very large directory trees use memory
  proportional to the number of files;
- no archive extraction, so files inside ZIPs or installers are not inspected;
- no scanning of alternate data streams, memory, or boot sectors;
- no signature updates or reputation lookup;
- symlinks inside directory trees are skipped to avoid loops and traversal
  outside the requested root;
- an explicitly scanned symlink is followed, and a symlink to a directory is
  walked at its resolved location;
- file contents can change while a scan is running; hashes and rule results
  describe the bytes Torvex observed during that scan;
- non-UTF-8 paths are displayed lossily in text and JSON output;
- GUI scans cannot be cancelled.

## Privacy

Torvex reads local paths selected by the user and performs hashing and rule
evaluation on the local machine. It contains no telemetry and makes no network
requests. Hash values and file metadata are shown in output because they are
useful evidence; review reports before sharing them publicly.

Building the project requires network access for Cargo dependencies. Third-party
YARA rules may import modules with their own behavior, so again: only load rule
sets you trust.

## Roadmap

The next priorities are:

1. Build a safely sourced, labeled evaluation corpus and report false-positive
   and false-negative rates before adding any confidence scoring.
2. Add cancellable scans and useful progress reporting for large directory trees.
3. Improve provenance reporting so findings identify the rule file that produced
   them, not only the rule name and namespace.
4. Add an automated GUI smoke test and manually verify X11 and non-Hyprland
   desktops, then document platform-specific behavior.
5. Evaluate archive extraction only after adding resource limits and a clear
   explanation of what is and is not inspected.

Any third-party rules or signature feeds will require license and provenance
review before inclusion.

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Do not attach
malware samples, private user files, or credentials to issues or pull requests.
For vulnerability reports, follow [SECURITY.md](SECURITY.md).

## License

Torvex is available under either the MIT License or Apache License, Version 2.0,
at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). Third-party dependencies and external rule
sets may have separate licenses.
