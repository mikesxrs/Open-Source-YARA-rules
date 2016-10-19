
rule vmprotect {
    meta:
        description = "VMProtect packed file"

        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $vmp0 = {2E766D7030000000}
        $vmp1 = {2E766D7031000000}

    condition:
        $mz at 0 and $vmp0 in (0x100..0x300) and $vmp1 in (0x100..0x300)
}

