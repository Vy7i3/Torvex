# YARA rules in Torvex

Torvex compiles `.yar` and `.yara` files from a rules directory with YARA-X.
Subdirectories are searched recursively, and files are compiled in sorted path
order within one namespace (`default`), so rules may reference rules from other
files in the same directory. A symlink used as the rules directory is resolved
once; symlinks inside the tree are not followed.

## The bundled rules are demo fixtures

`basic.yar` contains **harmless demo rules** used by the automated tests. They
match strings such as `TORVEX_YARA_EXAMPLE_TEXT`; they are not malware
signatures. Every rule sets `demo = true` so Torvex can warn that the active
rule set is not production detection content.

Do not present a match from `basic.yar` as malware detection.

## Loading rules

```sh
torvex scan ./samples --rules ./rules
torvex gui --rules ./rules
TORVEX_RULES_DIR=/opt/torvex/rules torvex scan ./samples
```

If no directory is configured, Torvex also checks `rules/` next to the binary,
then `./rules`, and finally uses the compiled-in demo fixtures.

An explicitly configured directory must exist and contain at least one valid
YARA file. Compilation errors are fatal. Empty directories found by automatic
discovery are skipped while discovery continues.

## Writing a rule

This is a safe, narrow example. A real rule needs a reviewed, documented source
of truth for the behavior it detects.

```yara
rule torvex_example_documented_marker : demo harmless
{
    meta:
        description = "Matches the documented Torvex test marker"
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
- Use tags to group rules by behavior or family, not to claim certainty.
- Prefer narrow strings and bounded conditions. Avoid short strings, broad
  wildcards, unbounded regular expressions, and conditions that can be
  expensive on large files.
- Use `private` or `global` rules deliberately; they change how other rules are
  evaluated.
- Do not import modules unless they are required and available in YARA-X.
- Add a harmless regression fixture and test both a matching and a nearby
  non-matching file.

Rule names should be stable and descriptive. Namespaces are currently shared,
and the CLI/GUI display the rule name and namespace only; the rule file path is
not yet reported.

## Provenance and licensing

Before adding third-party rules or a signature feed:

1. Record where the rules came from, including a commit or version.
2. Verify the license permits use and redistribution.
3. Keep the original attribution and license notice.
4. Review each rule for scope, false-positive risk, and performance.
5. Do not import rules whose provenance or redistribution rights are unclear.
6. Do not mix demo fixtures and production rules without marking the fixtures.

Rules are trusted input. A malicious or careless rule can consume resources or
change scan results. Only point Torvex at directories you trust.

## Verifying rule changes

From the repository root:

```sh
cargo test
```

Add test coverage for new rule behavior using harmless temporary files. Never
commit live malware or private user data. A useful test should show:

- the intended matching file;
- at least one similar non-matching file;
- the expected rule name and metadata in the scan result.

Then inspect a real run:

```sh
torvex scan ./path/to/fixtures --rules ./rules
```

A match is evidence for review, not proof that a file is malicious.
