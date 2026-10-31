rule test_benign_marker
{
    meta:
        author = "VECTRAID test suite"
        description = "Matches the word 'benign' - used only in tests"
        severity = "info"

    strings:
        $marker = "benign" ascii nocase

    condition:
        $marker
}
