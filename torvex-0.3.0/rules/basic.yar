/*
 * Harmless Torvex demo fixtures for testing the YARA-X integration.
 *
 * A match demonstrates the scanner path only. These are not malware
 * signatures. Every rule sets demo = true so Torvex can label the active rule
 * set and each finding as a test fixture.
 */

rule torvex_example_text : demo harmless
{
    meta:
        description = "Matches a harmless Torvex example text marker"
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"
        demo = true

    strings:
        $marker = "TORVEX_YARA_EXAMPLE_TEXT" ascii

    condition:
        $marker
}

rule torvex_example_json : demo harmless
{
    meta:
        description = "Matches a harmless Torvex example JSON marker"
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"
        demo = true

    strings:
        $marker = "\"torvex_test\": true" ascii

    condition:
        $marker
}

rule torvex_example_binary_marker : demo harmless
{
    meta:
        description = "Matches a harmless Torvex example binary marker"
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"
        demo = true

    strings:
        $marker = "TVX-DEMO-ONLY" ascii

    condition:
        $marker
}
