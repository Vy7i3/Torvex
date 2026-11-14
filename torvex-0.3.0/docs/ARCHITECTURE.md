# Torvex architecture

This document explains how Torvex is put together, and what it borrowed from two
mature scanners: [Lynis](https://cisofy.com/lynis/) for host auditing and
[Wazuh](https://documentation.wazuh.com/) for finding semantics and
correlation. The point of the comparison is not that Torvex is a replacement for
either. It is that a small local scanner can reuse their *framework ideas*
without inheriting their operational weight.

## 1. What Lynis does

Lynis is a shell-based security audit for Unix-like systems. Its framework has
five parts that matter here.

**Controls have stable identifiers.** Every test has a category prefix and a
number (`SSH-7408`, `KRNL-6000`, `AUTH-9230`, `FILE-6310`). The identifier is
the handle operators use: it appears in the report, it is what you suppress,
and it is what you search for when you want to understand a finding.

**Controls report a status, not a boolean.** A run prints `[ OK ]`,
`[ WARNING ]`, `[ SUGGESTION ]`, `[ FOUND ]`, `[ NOT FOUND ]`,
`[ SKIPPED ]` or `[ MANUAL ]`. `NOT FOUND` and `SKIPPED` mean *inapplicable* —
for example, SSH tests when no SSH server is installed. This distinction is the
difference between an honest audit and a score inflated by absent software.

**The hardening index is a ratio.** Each test awards earned and possible points.
The index is `earned / possible` over the tests that ran, not over every test in
the catalogue. Lynis documentation is explicit that it is a relative indicator,
not a security grade, and that it should only be compared against previous runs
of the same host.

**Profiles change the run.** `default.prf` and custom profiles enable or disable
tests (`is-enabled=1` in Lynis 3.x), set thresholds and record host identity.

**Output is dual.** A human transcript goes to `lynis.log`; machine-readable
`key=value` lines go to `lynis-report.dat`, including
`warning[]=ID|description|details|solution` records and `hardening_index=`.

### What Torvex adopted

| Lynis idea | Torvex implementation |
| --- | --- |
| Stable control ids with category prefixes | `SSH-7401`, `KRNL-6000`, ..., validated as `<3-4 letters>-<4 digits>` |
| Status vocabulary, including inapplicable | `passed`, `failed`, `suggestion`, `skipped`, `manual` |
| Hardening index as earned/possible over applicable controls | `score.index`, with category weights and a documented 60% credit for suggestions |
| Warnings vs suggestions | `failed` controls vs `suggestion` controls; only failures are findings above the "low" band |
| Profiles | JSON policy files (`--policy`) with category weights, disabled controls, severity overrides and a minimum score |
| Per-finding remediation | Every control carries `rationale` and `remediation`; surfaced in every report format |
| Dual output | JSON on stdout plus pretty output; both contain the same data |

### What Torvex changed, and why

* **Python instead of shell.** Controls are Python functions with typed
  outcomes, so they can be unit-tested against a fake filesystem root without a
  container or root privileges. Shell-based checks are hard to test hermetically
  and easy to break with quoting.
* **Read-only by construction.** The engine has no write path. External commands
  are restricted to a small allowlist of read-only probes, and only run against
  the live root; snapshot audits are fully hermetic.
* **JSON policy instead of a bespoke profile syntax.** Parsing is trivial and
  the same file can be consumed by CI.
* **ATT&CK and compliance fields on every control.** Lynis leaves mapping to
  enterprise editions and external tooling; Torvex puts indicative mappings in
  the finding so one report can be triaged for both engineering and compliance.
* **Honest empty roots.** A directory without `/etc` is not a Unix root, so all
  controls are skipped and the index is 0 instead of awarding points for absent
  files.

## 2. What Wazuh does

Wazuh is a distributed security platform: agents collect events and
configuration state, a manager decodes and matches rules, and an indexer and
dashboard store and present alerts. Four ideas transfer to a local scanner.

**Findings have a numeric level.** Rule `<level>` runs `0..16` and drives
alerting and active response. It is separate from a human label.

**Rules compose.** A rule can require a parent match (`<if_sid>`), a repetition
count (`<frequency>`) inside a window (`<timeframe>`), a suppression window
(`<ignore>`), a size cap, or a regex (`<match>`). A high-level rule fires when
eight low-level events occur in two minutes, not because a single event is
interesting on its own.

**Findings carry context.** Rules declare MITRE technique ids (`<mitre><id>`)
and a `<group>` of compliance tags such as `pci_dss_10.6.1`, `gdpr_IV_35.7.d`,
`nist_800_53_AU.6` and `tsc_CC7.2`.

**SCA policies are declarative and explain themselves.** A policy is YAML; each
check has `id`, `title`, `description`, `rationale`, `remediation`,
`compliance`, `references`, and a `condition` (`all`, `any`, `none`) over a list
of `rules`. That structure is why SCA output is actionable rather than a list of
failed strings.

### What Torvex adopted

| Wazuh idea | Torvex implementation |
| --- | --- |
| Numeric level `0..=15` | `Finding.level`, derived from severity: info 1, low 3, medium 6, high 8, critical 10 |
| `if_sid` parent selection | Correlation `ids` with prefix wildcards (`SSH-*`) |
| `frequency` / `timeframe` | Correlation `frequency` plus `same_target` (repeat within one file/control) |
| Composite detection | `require_sources` (two engines agree) and `require_tags` (credential + exfiltration) |
| MITRE and compliance metadata | Every YARA rule, native indicator and audit control carries `mitre` and `compliance` |
| SCA check shape | Audit controls carry id, title, rationale, remediation, compliance, evidence |
| Policy scoring | Category weights and a minimum-score threshold in the policy |
| Findings are *about* events | A correlated finding is `source: "correlation"` and lists its contributors in `related` |

### What Torvex deliberately does not do

* **No agent/manager split, no indexer, no log decoders.** Torvex scans a
  filesystem; there is no event stream to decode.
* **No arbitrary command execution per check.** Wazuh SCA can run commands.
  That is powerful and also a supply-chain and injection surface; Torvex parses
  configuration files and uses a fixed read-only probe allowlist.
* **No signature feed or CVE matching.** Package version comparison belongs to a
  vulnerability scanner with a maintained advisory database, not to this tool.
* **No regex engine per rule for content.** Regexes are expressive but slow on
  large files and easy to write catastrophically. Content matching uses
  literal multi-pattern matching, and structural analysis parses headers
  directly.

### Side-by-side

| | Lynis | Wazuh | Torvex |
| --- | --- | --- | --- |
| Scope | Host configuration | Host + network + logs, fleet | Files + one host, local |
| Control language | Shell | XML rules, YAML SCA | Rust/C++/Python + YARA |
| Scoring | Hardening index | Rule levels, SCA scores | Risk 0-100 + hardening index |
| Correlation | Limited | Full multi-event rules | Composite findings |
| Deployment | Local binary | Manager + agents + indexer | One binary |
| Output | Log + report.dat | Alerts + dashboard | JSON + HTML + web UI |

## 3. The Torvex pipeline

```
scan_path_with_options(path, options)
  ├─ load YARA-X rules (external dir, env, ./rules, embedded demo)
  ├─ compile native catalogue (33 indicators + 16 structural checks)
  ├─ walk, skipping vendor dirs and symlinks
  │    └─ per file: fingerprint_file_with_limit
  │         ├─ SHA-256 over every byte
  │         ├─ MIME from the first 8 KiB, extension fallback
  │         └─ content buffer capped at --max-file-size
  │         ├─ YARA-X scan(buffer)            → RuleMatch[]
  │         └─ native analyze(buffer)          → RuleMatch[] + FileAnalysis
      ├─ optional: Python audit (rooted, read-only) → AuditReport → findings
  ├─ correlation rules over all findings       → correlated findings
  ├─ sort findings, recompute summary and risk
  └─ ScanReport { results, findings, audit, failures, summary }
```

Each file is read once. Hashing always covers the whole file; only the
detection buffer is capped, so a multi-gigabyte file gets a correct hash without
being held in memory.

### The native core

`native/torvex_core.cpp` is a C++17 library with a stable C ABI
(`native/torvex_core.h`). It exists because these operations are tight loops
over untrusted bytes.

**Aho-Corasick.** All case-sensitive needles are compiled into one automaton and
all case-insensitive needles into a second. The build fills the transition table
during BFS, so scanning is one table lookup per byte regardless of how many
patterns exist. Rules are either "any needle" or "all needles" (logical AND),
which is enough to express download cradles and web shells without a regex
engine. Match counts and first offsets are capped per rule.

**Entropy and encoding.** Whole-buffer Shannon entropy, worst 4 KiB window
entropy (packed or encrypted regions), and the longest base64-alphabet run.
These become findings only for non-binary content, where they are meaningful;
packed binaries are caught by section analysis instead.

**Structural analysis.** Bounds-checked readers parse ELF program headers
(`PT_LOAD` W^X, entry inside a writable segment, `PT_GNU_STACK` executable,
missing `PT_GNU_RELRO`, `ET_EXEC`) and PE headers (`DllCharacteristics`
DYNAMICBASE/NX/CFG, `IMAGE_FILE_RELOCS_STRIPPED`, RWX sections, packer section
names, section entropy). Crafted fixtures in `native/test_native.cpp` verify
each field, and truncated headers are fuzzed by looping over every prefix
length.

**IOC extraction.** URLs, e-mail addresses and IPv4 literals, de-duplicated and
capped.

The Rust side keeps *all policy*: which patterns exist, how severe they are,
what they map to, and what the reader should do. The C++ side only reports what
it observed. That makes the dangerous code small and the policy reviewable.

### FFI safety

`#![deny(unsafe_code)]` applies crate-wide. Only `detection::ffi` opts in with a
module-level `allow`, and its invariants are:

* one owner per matcher, destroyed exactly once (`Drop`);
* strings returned by C are copied and freed with the C allocator, including on
  the error path;
* no slice outlives its call;
* the matcher is immutable after `build`, so `Send`/`Sync` are sound.

The native harness (`native/test_native.cpp`) tests the ABI without Rust, so an
ABI break is obvious before Cargo is involved.

### The audit engine

`python/torvex_audit.py` is one self-contained module, embedded in the binary
with `include_str!` and written to the temporary directory on first use. This
means an installed binary has a working audit with no package to install and no
checkout to point at. `torvex info` shows the materialised path.

`Context` provides read-only, rooted filesystem access: path traversal outside
the root returns `None`, reads are size-capped, and external commands only run
against the live root from an allowlist. That is what makes a fake root
sufficient for tests.

Scoring is Lynis-style. For each applicable control:

```
possible = control.weight * category.weight
earned   = possible * { passed: 1.0, suggestion: 0.6, failed/manual: 0.0 }
index    = round(100 * Σearned / Σpossible)
```

Statuses that are inapplicable (`skipped`) contribute neither points nor a
maximum. A root without `etc/` skips everything, so the index is 0 rather than
an unearned pass.

### Correlation

Correlation runs after every engine has contributed findings, and never
consumes its own output. A rule selects findings (`sources`, `ids`, `tags`,
`min_level`), applies a threshold (`frequency`), optionally restricts the group
to one target, and optionally requires multiple engines or tags. Each rule fires
at most once, producing a finding whose `related` field lists
`id @ target` pairs.

Order matters: file findings and audit findings must both exist before
`require_sources: ["audit", "yara"]` can fire, which is why the audit is merged
before correlation in `scan_path_with_options`.

### Reports

`ScanReport` is the single serialisable artifact, schema `torvex.report.v2`. It
carries per-file results (hash, size, type, verdict, matches, native analysis),
the flat findings list, audit report, failures and summary. The HTML renderer
embeds it as JSON in a `<script>` element and renders client-side, so filtering
and sorting need no server. The JSON is escaped for `</script>`, U+2028 and
U+2029.

The web dashboard serves the same template with a scan form. Mutations require a
process token, scans are confined to the root, and responses carry a restrictive
CSP. The token is a CSRF guard, not authentication: the server binds loopback by
default and is meant for a single local operator.

## 4. Testing strategy

| Layer | What is verified |
| --- | --- |
| `native/test_native.cpp` | Matcher semantics (AND/OR, case folding), entropy, base64 runs, IOC extraction, crafted ELF/PE headers, truncated headers, invalid input |
| Rust unit tests | FFI ownership, YARA metadata lifting, rule catalogue consistency, scoring, correlation semantics, HTML escaping, web routing and token checks, timestamp maths |
| Rust integration tests | CLI exit codes, JSON schema, engine selection, unreadable files, symlinks, HTML output, report re-rendering, hermetic audit, snapshot audit |
| Python unittest | Control catalogue integrity, insecure vs hardened fake roots, policy weights/overrides/skips, path-escape refusal, command allowlist, plugin loading, CLI JSON |

Fixtures are generated in temporary directories; no test needs root, a network
connection or a real malware sample.

## 5. Known gaps

* File scanning is sequential. The engines are fast, but a large tree is still
  single-threaded.
* Hash reputation and advisory matching are out of scope without a feed.
* Archives are scanned as bytes, not extracted.
* macOS and Windows have no host controls; only Linux is implemented.
* The GUI is a thin viewer over the same report model and is not part of the
  tested default build.
