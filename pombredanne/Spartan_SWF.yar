rule Spartan_SWF
{
    meta:
        author = "Jacob Soo Lead Re"
        date = "11-June-2016"
        version = "1.0"
    
    strings:
		$header = {46 57 53}
        $a1 = {73 6F 63 69 6F 64 6F 78 2E 75 74 69 6C 73 3A 42 61 73 65 36 34}
        $a2 = {0C 5F 65 6E 63 6F 64 65 43 68 61 72 73 0C 5F 64 65 63 6F 64 65 43 68 61 72 73 06 65 6E 63 6F 64 65 06 64 65 63 6F 64 65 0E 49 6E 69 74 45 6E 63 6F 72 65 43 68 61 72 0E 49 6E 69 74 44 65 63 6F 64 65 43 68 61 72}
    condition:
        $header at 0 and all of ($a*)
}
