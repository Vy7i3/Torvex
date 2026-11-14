# Rules in Torvex

Torvex has two rule languages, because it has two kinds of detection.

* **YARA-X** (`.yar`, `.yara`) for declarative content rules.
* **Native indicators** (`src/detection/native.rs`) for literal multi-pattern
  matching and structural analysis that benefits from the C++ core.

Correlation rules (`rules/correlation.json`) are a third, much smaller format:
they do not match files, they combine findings.

## The YARA packs

| File | Rules | Purpose |
| --- | --- | --- |
| `basic.yar` | 3 | Harmless demo fixtures. Every rule sets `demo = true`. |
| `suspicious_scripts.yar` | 6 | PowerShell cradles, reverse shells, miners, ransom notes, anti-forensics |
| `webshells.yar` | 4 | PHP/JSP/ASP command execution and encoded payloads |
| `iocs.yar` | 5 | Cloud keys, private key material, chat webhooks, history upload |

`basic.yar` is the compiled-in fallback. It exists to prove the scanner path
works; it is not detection content, and Torvex labels it everywhere.

## Rule metadata

Torvex reads these metadata keys:

```yara
rule tvx_example : loader powershell
{
    meta:
        title = "Short human title"
        description = "What was observed and why it matters."
        severity = "high"                 // info | low | medium | high | critical
        mitre = "T1059.001,T1105"         // comma or space separated
        compliance = "PCI DSS 6.4"        // comma separated
        remediation = "What the reader should do next."
        author = "Your Name"
        license = "MIT OR Apache-2.0"
        demo = true                       // only for harmless fixtures

    strings:
        $a = "DownloadString" nocase
        $b = "IEX" nocase

    condition:
        all of them
}
```

Notes:

* `severity` is authoritative. Without it, Torvex falls back to tags
  (`critical`, `malware`, `webshell`, `suspicious`, ...), and finally to
  medium. Demo fixtures are always capped at low.
* Tags are identifiers: letters, digits and underscores. **Hyphens are a syntax
  error in YARA tags** (`reverse-shell` will not compile; use
  `reverse_shell`).
* `condition: all of them` is the idiomatic way to express a compound signal
  such as "a download primitive *and* an evaluator". Prefer it over long
  `and`/`or` chains; a rule that fires on one generic string is noise.

## Loading rules

```sh
torvex scan ./samples --rules ./rules
TORVEX_RULES_DIR=/opt/torvex/rules torvex scan ./samples
```

If no directory is configured, Torvex checks `rules/` next to the binary, then
`./rules`, then uses the embedded demo fixtures.

An explicitly configured directory must exist and contain at least one valid
YARA file. Compilation errors are fatal. Empty directories found by automatic
discovery are skipped while discovery continues.

```sh
torvex rules list --rules ./rules      # ids, namespaces, demo markers
torvex rules validate --rules ./rules  # compile check
```

## Correlation rules

```json
{
  "id": "TVX-CORR-004",
  "title": "Two independent content engines agree",
  "description": "YARA and the native engine both fired on one file.",
  "severity": "high",
  "min_level": 6,
  "frequency": 2,
  "same_target": true,
  "require_sources": ["yara", "native"],
  "remediation": "Prioritise this file in triage.",
  "mitre": ["T1204"],
  "compliance": []
}
```

Semantics:

* `ids` — select by finding id; a trailing `*` is a prefix wildcard.
* `sources` / `tags` — select by source or tag (any of).
* `min_level` — ignore findings below this level.
* `frequency` — minimum number of matching findings.
* `same_target` — require the matches to share one file or control target.
* `require_sources` — every listed engine must be represented among the matches.
* `require_tags` — every listed tag must appear among the matches.
* `severity` — the level of the correlated finding.

A rule fires at most once and never consumes other correlated findings, so
there is no recursion. `torvex scan . --no-correlation` disables the stage.

## Writing a rule

This is a safe, narrow example. A real rule needs a reviewed, documented source
of truth for the behaviour it detects.

```yara
rule tvx_example_documented_marker : demo harmless
{
    meta:
        title = "Documented Torvex test marker"
        description = "Matches the documented Torvex test marker."
        severity = "low"
        author = "Your Name"
        license = "MIT OR Apache-2.0"
        reference = "corpus:torvex-demo-marker-v1"
        demo = true

    strings:
        $marker = "TORVEX_YARA_EXAMPLE_TEXT" ascii

    condition:
        $marker
}
```

Guidance:

- Add a `description` that explains the evidence the rule matches.
- Add `author` and `license` metadata.
- Add `reference` metadata with a source URL, advisory identifier, or corpus
  record when one exists.
- Set `demo = true` for harmless test fixtures. Do not set it for detection
  content.
- Use tags to group rules by behaviour, not to claim certainty.
- Prefer narrow strings and bounded conditions. Avoid short strings, broad
  wildcards, unbounded regular expressions, and conditions that can be
  expensive on large files.
- Use `private` or `global` rules deliberately; they change how other rules are
  evaluated.
- Add a harmless regression fixture and a nearby non-matching file.

## Native indicators

Add an entry to `RULES` in `src/detection/native.rs` with `id`, `title`,
`description`, `severity`, `needles`, `tags`, `mitre`, `compliance` and
`remediation`, then add a fixture to the module tests. Use `require_all: true`
when the behaviour needs several strings together.

Structural indicators are two-sided: the C++ analyser emits an id, and
`STRUCTURAL` in the same file supplies its policy. Keep the ids in sync; the
native harness and the Rust catalogue test both check for duplicates.

## Provenance and licensing

Before adding third-party rules or a signature feed:

1. Record where the rules came from, including a commit or version.
2. Verify the licence permits use and redistribution.
3. Keep the original attribution and licence notice.
4. Review each rule for scope, false-positive risk, and performance.
5. Do not import rules whose provenance or redistribution rights are unclear.
6. Do not mix demo fixtures and production rules without marking the fixtures.

Rules are trusted input. A malicious or careless rule can consume resources or
change scan results. Only point Torvex at directories you trust.

## Verifying rule changes

```sh
cargo test
python3 -m unittest discover -s python -v
cargo clippy --all-targets -- -D warnings
```

A useful rule test should show:

- the intended matching file;
- at least one similar non-matching file;
- the expected rule name, severity and metadata in the result.

Then inspect a real run:

```sh
torvex scan ./path/to/fixtures --rules ./rules
torvex scan ./path/to/fixtures --rules ./rules --format html
```

A match is evidence for review, not proof that a file is malicious.
