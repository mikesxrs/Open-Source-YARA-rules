
rule conbot_packer {
    meta:
        decoder = "conbot_packer.py"

    strings:
        $pic_code = { FCE8 8600 0000 6089 E531 D264 8B52 308B 520C 8B52 148B 7228 0FB7 4A26 31FF 31C0 AC3C 617C 022C 20C1 CF0D 01C7 E2F0 5257 8B }

    condition:
        IsPeFile and $pic_code
}

