rule NIDS_Test_Simple {
    meta:
        description = "Simple test pattern"
        severity = "0.5"
        category = "test"
    strings:
        $test = "NIDS_TEST_PAYLOAD"
    condition:
        $test
}

rule NIDS_Test_Hex {
    meta:
        description = "Hex pattern test"
        severity = "0.8"
        category = "test"
    strings:
        $hex = { DE AD BE EF }
    condition:
        $hex
}

rule NIDS_Test_Multiple {
    meta:
        description = "Multiple string test"
        severity = "0.6"
        category = "test"
    strings:
        $a = "ALPHA_MARKER"
        $b = "BETA_MARKER"
    condition:
        $a and $b
}

rule NIDS_Test_NoMatch {
    meta:
        description = "This should never match test data"
        severity = "1.0"
        category = "test"
    strings:
        $impossible = "THIS_STRING_WILL_NEVER_APPEAR_IN_TEST_DATA_12345678"
    condition:
        $impossible
}
