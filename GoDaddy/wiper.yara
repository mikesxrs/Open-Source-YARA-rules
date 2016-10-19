
rule wiper {
    meta:
        description = "Wiper malware deployed in late 2014 skywiper attacks"

    strings:
        // 760C35A80D758F032D02CF4DB12D3E55 @ 0x40124A
        $decryption_main_loop = {8bcbe8????????8a143e32d088143e463bf57cec5f}
        // 760C35A80D758F032D02CF4DB12D3E55 @ 0x40118d
        $context_init_loop1 = { 8b790c8b411033f78971088bf033f789710c8b710833c64b89411075e3 }
        // 760C35A80D758F032D02CF4DB12D3E55 @ 0x4011b4
        $context_init_loop2 = { 8b510c8b41100bf28971088bf00bf289710c8b71080bc64f89411075e3 }
        $MZ = "MZ"

    condition:
        $MZ at 0 and 2 of them
}

rule wiper_payload_dropper {
    meta:
        description = "Wiper implant"
        filename = "iissvr.exe"

    strings:
        $MZ = "MZ"

        // the following 3 are used to transfer html/wav/jpg data from the resource section (these include the resource name following the http data)
        $html={485454502F312E3120323030204F4B0D0A436F6E74656E742D4C656E6774683A2025640D0A436F6E74656E742D547970653A20746578742F68746D6C0D0A4163636570742D52616E6765733A2062797465730D0A5365727665723A204D6963726F736F66742D4949532F362E300D0A0D0A000000525352435F48544D4C00}

        $wav={485454502F312E3120323030204F4B0D0A436F6E74656E742D4C656E6774683A2025640D0A436F6E74656E742D547970653A20696D6167652F6A7065670D0A4163636570742D52616E6765733A2062797465730D0A5365727665723A204D6963726F736F66742D4949532F362E300D0A0D0A0000525352435F4A504700} 

        $jpg={485454502F312E3120323030204F4B0D0A436F6E74656E742D4C656E6774683A2025640D0A436F6E74656E742D547970653A20617564696F2F7761760D0A4163636570742D52616E6765733A2062797465730D0A5365727665723A204D6963726F736F66742D4949532F362E300D0A0D0A000000525352435F57415600}

    condition:
        $MZ at 0 and ($html or $wav or $jpg)
}

/*
// Moderate confidence that this rule matches a legitimate driver component used by the wiper malware
// as opposed to it having been signed by a stolen certificate.
// It's commented out here because it could hit on legitimate software and the userland component
// will be detected by signatures anyway.
rule wiper_driver_component {
    meta:
        description = "Wiper implant"
        filename = "usbdrv3.sys"

    strings:
        $MZ = "MZ"

        // 86E212B7FC20FC406C692400294073FF @ 0x15F55
        $switch_table1 = {4C89B424C8000000488B4F088B414883F802742D83F807742883F81F742383F824741E83F82D741983F831741483F836740F83F830740ABB240000C0E9}
        // @ 0x164D8
        $switch_table2 = {488BF08B484883F903741D83F908741883F909741383F914740E83F920740983F9350F}

    condition:
        $MZ at 0 and $switch_table1 and $switch_table2
}
*/

rule wiper_payload_dropper2 {
    meta:
        description = "Wiper implant"
        filename = "ams.exe"

    strings:
        $MZ = "MZ"

        // 7E5FEE143FB44FDB0D24A1D32B2BD4BB
        $process_hacker_ascii = {5c4465766963655c4b50726f636573734861636b657232}
        $process_hacker_unicode = {5c004400650076006900630065005c004b00500072006f0063006500730073004800610063006b006500720032000000}
        $mcshield_string = {53595354454d5c43757272656e74436f6e74726f6c5365745c73657276696365735c4d63536869656c6400}

    condition:
        $MZ at 0 and ($process_hacker_ascii or $process_hacker_unicode) and $mcshield_string
}

