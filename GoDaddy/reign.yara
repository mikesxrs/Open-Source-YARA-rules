rule Reign_1 {
    meta:
        info = "Reign"

    strings:
            $string_decode = {55 8b ec 5d 8b 45 08 0b c0 74 0c eb 05 fe 08 fe 08 40 80 38 00 75 f6}

    condition:
            $string_decode
}


rule Reign_Driver {
    meta:
        info = "Reign Driver Component (32-bit)"

    strings:
        // 2C8B9D2885543D7ADE3CAE98225E263B
        // This is dead space at the end of the config block that will be constant between reconfigurations
        $config_block_padding = {c739f2c8ee70ebc9cf31fac0e678d3f1f709c2f8de40dbf9ff01caf0}

    condition:
        $config_block_padding
}


