rule sakula_packed_v2_0
{
    meta:
        description = "Sakula packer v2.0 - The bytes string matchs 2 concatenated functions. The first function returns the offset of the second function, and the second function returns the payload offset (hardcoded)"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m = { 55 8B EC 51 53 56 57 E8  00 00 00 00 58 05 13 00 00 00 89 45 FC 8B 45 FC  5F 5E 5B 8B E5 5D C3 4D }

        $MZ = "MZ"
    condition:
        all of them
}

