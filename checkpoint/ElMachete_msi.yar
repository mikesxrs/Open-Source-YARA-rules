rule ElMachete_msi
{
    meta:
        author = "CPR"
        reference = "https://research.checkpoint.com/2022/state-sponsored-attack-groups-capitalise-on-russia-ukraine-war-for-cyber-espionage/"
        hash1 = "ED09DA9D48AFE918F9C7F72FE4466167E2F127A28A7641BA80D6165E82F48431"
    strings:
        $s1 = "MSI Wrapper (8.0.26.0)"
        $s2 = "Windows Installer XML Toolset (3.11.0.1701)"
        $s3 = "\\Lib\\site-packages\\PIL\\"
        $s4 = "\\Lib\\site-packages\\pyHook\\"
        $s5 = "\\Lib\\site-packages\\requests\\"
        $s6 = "\\Lib\\site-packages\\win32com\\"
        $s7 = "\\Lib\\site-packages\\Crypto\\"
    condition:
        4 of them
}
