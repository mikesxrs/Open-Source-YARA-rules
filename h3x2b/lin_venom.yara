rule venom_20170125 : malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects Venom samples - 20170125"
        // Check also:
        // https://wiki.egi.eu/w/images/c/ce/Report-venom.pdf

    strings:
        $venom_00 = "justCANTbeSTOPPED"
        $venom_01 = "%%VENOM%AUTHENTICATE%%"
        $venom_02 = "%%VENOM%OK%OK%%"


    condition:
        //ELF magic
        uint32(0) == 0x464c457f and

        //Contains all of the strings
        all of ($venom_*)
}
