# Torvex

![Status: beta](https://img.shields.io/badge/status-beta-yellow)
![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![Rust: 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange)
![Engines: YARA-X + C++ + Python](https://img.shields.io/badge/engines-YARA--X%20%C2%B7%20C%2B%2B%20%C2%B7%20Python-informational)

Torvex is a local-first security scanner. It answers two different questions in
one report:

* **What is in these files?** — YARA-X rules plus a native C++ indicator engine
  that does multi-pattern matching, entropy analysis and ELF/PE structural
  inspection.
* **How is this host configured?** — a Python, Lynis-style configuration
  assessment with stable control IDs, a hardening index, and remediation
  guidance.

Every engine emits the same finding model: severity, a Wazuh-style numeric
level, ATT&CK mapping, compliance tags and a fix. A correlation engine then
combines weak signals into compound findings. The result is a terminal report,
JSON, a self-contained HTML dashboard, or a local web UI.

> **Torvex is not an antivirus.** It has no maintained malware-signature feed,
> no real-time protection, no quarantine and no remediation. A rule match is
> evidence to review, not proof of malware, and a clean result only means that
> no loaded rule matched. Do not rely on it as your only protection.

Version 0.3.0. The project follows `0.x` versioning.

## Contents

- [What is new in 0.3](#what-is-new-in-03)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [The finding model](#the-finding-model)
- [Scoring](#scoring)
- [Correlation](#correlation)
- [Reports and dashboards](#reports-and-dashboards)
- [Security model](#security-model)
- [Limitations](#limitations)
- [Development](#development)
- [Rule authoring](#rule-authoring)
- [License](#license)

## What is new in 0.3

| Area | 0.2 | 0.3 |
| --- | --- | --- |
| Content engines | YARA-X | YARA-X **and** a C++ Aho-Corasick indicator engine with ELF/PE analysis |
| Host assessment | — | Python audit engine, 57 controls, hardening index |
| Findings | rule name + description | unified model with severity, level, ATT&CK, compliance, remediation |
| Correlation | — | Wazuh-style composite rules (frequency, multi-source, tag pairing) |
| UI | desktop GUI only | web dashboard + static HTML report + rich CLI; GUI still optional |
| Rules | 3 demo fixtures | 17 YARA rules in 4 packs, 33 native indicators, 16 structural checks |
| Tests | 40 | 162 checks across Rust, C++ and Python |

See [CHANGELOG.md](CHANGELOG.md) for the full list.

## Architecture

```
                 ┌───────────────────────────────────────────────┐
   file bytes ──▶│  scanner: one read, one hash, one buffer      │
                 └───────┬───────────────────────────┬───────────┘
                         │                           │
                 ┌───────▼────────┐          ┌───────▼──────────────┐
                 │ YARA-X         │          │ native C++ core      │
                 │ rule packs     │          │ Aho-Corasick (1 pass)│
                 │ severity/mitre │          │ entropy · ELF · PE   │
                 └───────┬────────┘          │ IOC extraction       │
                         │                   └───────┬──────────────┘
                         │                           │
                 ┌───────▼───────────────────────────▼───────────┐
                 │ unified findings (severity, level, mappings)  │
                 └───────▲───────────────────────────▲───────────┘
                         │                           │
                 ┌───────┴────────┐          ┌───────┴──────────────┐
                 │ Python audit   │          │ correlation rules    │
                 │ 57 controls    │          │ frequency · sources  │
                 │ hardening index│          │ tag pairing          │
                 └───────┬────────┘          └───────┬──────────────┘
                         └───────────┬───────────────┘
                                     ▼
              pretty CLI · JSON · HTML dashboard · local web UI
```

Design notes, and a comparison with Lynis and Wazuh, are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

- **Rust 1.95+** and Cargo.
- **A C++17 compiler** (`g++` or `clang++`). The native engine is built by
  `build.rs` through the `cc` crate.
- **Python 3.10+** for the host audit. It is optional: everything else works
  without it, and `torvex scan` reports that the audit is unavailable.
- Linux is the tested platform. macOS and Windows may compile; the audit
  controls are Linux-specific.

No system YARA installation is needed: YARA-X is a Rust library.

The optional desktop GUI (`--features gui`) additionally needs X11/Wayland and
OpenGL development headers. The default build is headless.

On Ubuntu/Debian:

```sh
sudo apt-get install --yes build-essential python3
```

## Install

```sh
git clone https://github.com/Vy7i3/Torvex.git
cd Torvex
cargo build --release
./target/release/torvex --help
```

Optional desktop build:

```sh
sudo apt-get install --yes pkg-config libgl1-mesa-dev libwayland-dev \
  libx11-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev
cargo build --release --features gui
```

## Usage

### Scan files

```sh
torvex scan .
torvex scan /srv/www --fail-on high
torvex scan . --json --output report.json
torvex scan . --format html --output report.html
```

Vendor and build directories (`.git`, `node_modules`, `target`, `__pycache__`,
`.venv`, `dist`, `build`, ...) are skipped by default; `--include-vendor`
scans them anyway.

### Audit a host

```sh
torvex audit --root /                 # live host
torvex audit --root /mnt/image        # snapshot / mounted image
torvex audit --json --output audit.json
torvex audit --skip SSH-7401 --fail-on high
```

The audit is strictly read-only. It never changes a setting.

### Scan and audit together

```sh
torvex scan /srv --audit                      # audit the live host
torvex scan /mnt/image --audit --audit-root /mnt/image   # audit the snapshot
```

When the audit runs, correlated rules can combine a file finding with a host
misconfiguration (`TVX-CORR-003`).

### Dashboard

```sh
torvex serve --root .                 # http://127.0.0.1:8787
torvex serve --root /srv --port 9000
```

The dashboard scans within `--root` only, requires a per-process request token
for scans, and binds loopback by default. See
[Security model](#security-model).

### Other commands

```sh
torvex report report.json --output report.html   # re-render saved JSON
torvex rules list                                # active rules + demo markers
torvex rules validate                            # compile check
torvex info                                      # engine versions and capabilities
torvex version
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Complete scan, nothing at or above `--fail-on` |
| `1` | Complete scan with blocking findings |
| `2` | Incomplete or failed scan (unreadable files, bad rules, audit failure) |

`--fail-on` accepts `none`, `any`, `info`, `low`, `medium`, `high` or
`critical`. `scan` defaults to `any`; `audit` defaults to `medium`, so audit
suggestions do not fail CI by default.

## The finding model

Every finding carries:

```json
{
  "id": "TVX-NAT-008",
  "title": "Interactive reverse shell",
  "description": "`bash -i >&` redirects an interactive shell to a socket.",
  "severity": "critical",
  "level": 10,
  "source": "native",
  "target": "/srv/www/upload.sh",
  "category": null,
  "evidence": [{ "kind": "first offset", "value": "0x18" }],
  "tags": ["shell", "reverse-shell"],
  "mitre": ["T1059.004", "T1071"],
  "compliance": [],
  "remediation": "Kill the process, capture its parent chain, and isolate the host.",
  "demo": false
}
```

* **severity** — `info`, `low`, `medium`, `high`, `critical`.
* **level** — `0..=15`, Wazuh-style, used for sorting and thresholds.
* **source** — `yara`, `native`, `audit` or `correlation`.
* **demo** — a harmless fixture. Demo findings never contribute risk points.

## Scoring

**Risk score (0-100).** `min(100, Σ points)` with critical 35, high 18, medium
7, low 2, info 0. Demo fixtures contribute 0. It is a triage ordering, not a
probability.

**Hardening index (0-100).** Adopted from Lynis: each applicable control has a
weight; passing earns all of it, a suggestion earns 60%, failing earns none.
The index is `earned / possible` over applicable controls only, weighted by
category. Inapplicable controls (no sshd, no auditd) are *skipped* and do not
inflate the score. A directory without `/etc` is not treated as a host: every
control is skipped and the index is 0.

The index is relative to one host and one policy. Never compare two different
machines, and never read it as "percent secure".

## Correlation

Correlation rules live in [rules/correlation.json](rules/correlation.json) and
apply the parts of the Wazuh rule engine that make sense for findings:

| Field | Meaning |
| --- | --- |
| `ids` | Select findings by id; a trailing `*` is a prefix wildcard (`SSH-*`) |
| `min_level` | Ignore findings below this level |
| `frequency` | Minimum number of matching findings |
| `same_target` | Require the matches to share one file or control target |
| `require_sources` | Every listed engine must be represented |
| `require_tags` | Every listed tag must appear among the matches |

Shipped rules (8): three severe indicators in one file (`TVX-CORR-001`),
several SSH gaps (`TVX-CORR-002`), content findings plus host failures
(`TVX-CORR-003`), YARA and native agreeing on one file (`TVX-CORR-004`),
widespread medium findings (`TVX-CORR-005`), credentials beside an exfiltration
channel (`TVX-CORR-006`), persistence beside privilege escalation
(`TVX-CORR-007`) and audit-trail tampering indicators (`TVX-CORR-008`).

Correlated findings are `source: "correlation"` and list their contributing
findings in `related`. They never feed back into correlation.

## Reports and dashboards

* **Terminal** — severity-grouped findings, risk bar, host hardening bar,
  per-file detail, failures.
* **JSON** — schema `torvex.report.v2`, stable enough for automation. The
  per-file `results` array is preserved alongside the flat `findings` array.
* **HTML** — one file with inline CSS/JS, no external assets. Filter by
  severity/source, search, sort, expand findings, export JSON, print to PDF.
  Works offline and from an email attachment.
* **Web** — the same dashboard with a scan form.

## Security model

* **Read-only.** Torvex never writes to, deletes, quarantines or repairs a
  scanned file. It does not modify host configuration.
* **Local-first.** No network requests are made by the scanner. Nothing is
  uploaded.
* **`unsafe` is denied crate-wide** and allowed only in `detection::ffi`, the
  C ABI boundary. That module owns pointers, frees native strings with the
  matching allocator, and is covered by unit tests plus a native test harness.
* **Bounded work.** Per-file content buffering is capped (`--max-file-size`,
  default 64 MiB), YARA evaluation has a 30-second timeout, the native core
  caps matches, IOCs and scan bytes, and the audit has a 120-second timeout.
* **Web dashboard.** Loopback by default, a 128-bit per-process token on
  mutations (a cross-origin page cannot read it, and a custom header forces a
  preflight this server never answers), scans restricted to `--root`,
  request/body caps, `no-store`, `nosniff`, `DENY` framing and a restrictive
  CSP.
* **Trusted input.** YARA rules and audit policies are trusted code. Only point
  Torvex at directories and policies you trust.

## Limitations

* No real-time or background protection, quarantine, or archive extraction.
* No malware-signature feed or reputation service.
* No calibrated detection probability.
* Symlinks inside a directory tree are not followed.
* The host audit covers Linux configuration, not vulnerability scanning: it
  does not compare package versions against CVE feeds.
* Compliance and ATT&CK mappings are indicative, not a certification.
* `scan --audit` on a path defaults the audit root to `/`; use `--audit-root`
  for snapshots.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
python3 -m unittest discover -s python -v

# native C++ harness, independent of Cargo
g++ -std=c++17 -O2 native/torvex_core.cpp native/test_native.cpp -o /tmp/torvex-native
/tmp/torvex-native

# optional desktop GUI
cargo check --locked --features gui
```

Current status: **82 Rust tests (57 unit, 2 binary, 23 integration), 30 Python
tests and 50 native assertions pass**. `cargo clippy --locked --all-targets --
-D warnings` and `cargo fmt --check` are clean, and the declared MSRV is
checked with Rust 1.95.0 in CI.

Adding a capability:

* **Native indicator** — add a `NativeRule` to `src/detection/native.rs` with
  severity, tags, ATT&CK, remediation and a test fixture.
* **Structural check** — emit an id from `native/torvex_core.cpp` and add the
  matching `StructuralRule`.
* **YARA rule** — see [rules/README.md](rules/README.md) and set `severity`.
* **Host control** — add a `@control(...)` function to
  `python/torvex_audit.py`; keep it read-only and test it against a fake root.
* **Correlation rule** — add an entry to `rules/correlation.json`.

## Rule authoring

[rules/README.md](rules/README.md) documents provenance, severity metadata and
the demo-fixture convention. Short version:

* Narrow strings, bounded conditions, documented source for every claim.
* Set `severity` and `mitre` metadata so the report can explain the finding.
* Mark harmless fixtures with `demo = true`; they are labelled and score 0.
* Never commit live malware.

## License

MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
