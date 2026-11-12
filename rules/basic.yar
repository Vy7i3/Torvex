/*
 * Harmless Torvex examples for testing the YARA-X integration.
 * A match demonstrates the scanner path only; it is not a malware signature.
 */

rule torvex_example_text
{
    meta:
        description = "Matches a harmless Torvex example marker"
        author = "Torvex"

    strings:
        $marker = "TORVEX_YARA_EXAMPLE_TEXT" ascii

    condition:
        $marker
}

rule torvex_example_json
{
    meta:
        description = "Matches a harmless Torvex example JSON marker"
        author = "Torvex"

    strings:
        $marker = "\"torvex_test\": true" ascii

    condition:
        $marker
}

rule torvex_example_binary_marker
{
    meta:
        description = "Matches a harmless Torvex example binary marker"
        author = "Torvex"

    strings:
        $marker = "TVX-DEMO-ONLY" ascii

    condition:
        $marker
}
