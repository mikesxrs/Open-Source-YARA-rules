
rule appraisel_exe {
    strings:
        $decode_function = {8B3883C0048D8FFFFEFEFEF7D723CF23CD75398B3883C0048D8FFFFEFEFEF7D723CF23CD75268B3883C0048D8FFFFEFEFEF7D723CF23CD75138B3883C0048D8FFFFEFEFEF7D723CF23CD74B4}
    condition:
        $decode_function
}

rule appraisel_exe_payload {
    meta:
        decoder = "appraisel_exe_payload.py"

    strings:
        $filename1 = "%s\\Tmp" wide
        $filename2 = "%s\\Volume Panel" wide
        $filename3 = "\\VolPanlu.exe" wide
        $filename4 = "%s\\updstat.bin" wide
        $filename5 = "%s\\srvstat.bin" wide

        $string1 = "Panlu" wide fullword

        // AFC5BE36ED870435A2E3C9714CCFFD44 @ 0x4012f0
        $3min_uptime_test = {FF15????????3D20BF0200730B68C0D40100FF15????????680F270000}

    condition:
        4 of ($filename*,$string1) or $3min_uptime_test
}

