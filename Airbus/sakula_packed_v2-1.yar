rule sakula_packed_v2_1
{
    meta:
        description = "Sakula packer v2.1 - The bytes string matchs a specific decryption routine. It starts by xoring the payload many times (an even number) with 0x32. It is cryptographically useless, but it simulates a Sleep. Then, it decrypts the payload with a xor 0x33"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m = { 33 C0 B2 32 85 F6 74 0D  30 14 38 8D 0C 38 40 FE C2 3B C6 72 F3 81 FB FF  FF 01 00 74 0B 43 81 FB 00 00 00 01 7C DA EB 15  33 C9 B2 33 85 F6 74 0D 30 14 39 8D 04 39 41 FE  C2 3B CE 72 F3 83 EC 0C}

    condition:
        all of them
}

