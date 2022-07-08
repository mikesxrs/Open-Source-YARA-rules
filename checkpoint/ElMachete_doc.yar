rule ElMachete_doc
{
    meta:
        author = "CPR"
        reference = "https://research.checkpoint.com/2022/state-sponsored-attack-groups-capitalise-on-russia-ukraine-war-for-cyber-espionage/"
        hash1 = "8E1360CC27E95FC47924D9BA3EF84CB8FA9E142CFD16E1503C5277D0C16AE241"
    strings:
        $s1 = "You want to continue with the Document" ascii
        $s2 = "certutil -decode" ascii
        $s3 = /C:\\ProgramData\\.{1,20}\.txt/
        $s4 = /C:\\ProgramData\\.{1,20}\.vbe/
    condition:
        uint16be(0) == 0xD0CF and 2 of ($s*)
}
