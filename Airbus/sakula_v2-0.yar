rule sakula_v2_0
{
    meta:
        description = "Sakula v2.0 - The bytes string matchs a specific decryption routine (xor 0x33) (VirtualAlloc + memcpy + loop)"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"

    strings:
        $m = { 8B 75 DC 2B F3 6A 40 68  00 10 00 00 56 6A 00 FF 15 04 20 40 00 8B F8 85  FF 74 4A 56 8B 4D E0 03 CB 51 57 E8 3C 02 00 00  83 C4 0C C7 45 FC 00 00 00 00 B3 33 33 D2 89 55  D8 88 5D E7 3B D6 73 11 0F B6 CB 0F B6 04 3A 33  C8 88 0C 3A FE C3 42 EB E5 FF D7 EB }

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}