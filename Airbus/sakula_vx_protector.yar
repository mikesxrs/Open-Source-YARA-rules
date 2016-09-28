

rule vx_protector  {
    meta:
        description = "vx protector (used as a protection layer by Sakula) - The bytes string match a specific layer of protection inserted manually before the real code. It decrypts the real code and jumps on it."
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = { 89 FF 55 89 E5 83 EC 20 A1 08 30 40 00 83 F8 00 75 0F A1 0C 30 40 00 83 F8 00 75 05 E9 95 00 00 00 E8 FA 60 00 00 89 45 FC 68 88 13 00 00 E8 F3 60 00 00 E8 C8 5F 00 00 83 F8 00 74 E4 89 45 EC E8 DB 60 00 00 2B 45 FC 3D 88 13 00 00 7C D2 8D 45 F8 50 E8 AE 5F 00 00 83 F8 00 74 C4 A1 08 30 40 00 83 F8 00 74 2C 68 E8 03 00 00 E8 B5 60 00 00 8D 45 F0 50 E8 8C 5F 00 00 83 F8 00 74 E8 8B 45 FC 8B 5D F4 39 D8 74 98 8B 45 F8 8B 5D F0 39 D8 74 D4 A1 0C 30 40 00 83 F8 00 74 19 68 88 13 00 00 E8 7F 60 00 00 E8 54 5F 00 00 83 F8 00 74 E2 3B 45 EC 90 90 FF 35 00 30 40 00 B8 1A 30 40 00 BB 71 32 40 00 29 C3 53 68 1A 30 40 00 E8 25 1B 00 00 8D 45 FC 50 6A 40 B8 2A 11 40 00 BB F8 2B 40 00 29 C3 53 68 2A 11 40 00 E8 3C 60 00 00 FF 35 04 30 40 00 B8 2A 11 40 00 BB F8 2B 40 00 29 C3 53 68 2A 11 40 00 E8 EB 1A 00 00 8D 45 FC 50 FF 30 B8 2A 11 40 00 BB F8 2B 40 00 29 C3 53 68 2A 11 40 00 E8 02 60 00 00 EC EC EC EC EC EC}

    condition:
        all of them
}