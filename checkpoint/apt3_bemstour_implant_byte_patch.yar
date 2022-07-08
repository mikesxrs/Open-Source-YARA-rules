rule apt3_bemstour_implant_byte_patch
{
meta:

description = "Detects an implant used by Bemstour exploitation tool (APT3)"
reference = "https://research.checkpoint.com/2019/upsynergy/"
author = "Mark Lechtik"
company = "Check Point Software Technologies LTD."
date = "2019-06-25"
sha256 = "0b28433a2b7993da65e95a45c2adf7bc37edbd2a8db717b85666d6c88140698a"

/*

0x41b7e1L C745B8558BEC83                mov dword ptr [ebp - 0x48], 0x83ec8b55
0x41b7e8L C745BCEC745356                mov dword ptr [ebp - 0x44], 0x565374ec
0x41b7efL C745C08B750833                mov dword ptr [ebp - 0x40], 0x3308758b
0x41b7f6L C745C4C957C745                mov dword ptr [ebp - 0x3c], 0x45c757c9
0x41b7fdL C745C88C4C6F61                mov dword ptr [ebp - 0x38], 0x616f4c8c

*/

strings:

$chunk_1 = {

C7 45 ?? 55 8B EC 83
C7 45 ?? EC 74 53 56
C7 45 ?? 8B 75 08 33
C7 45 ?? C9 57 C7 45
C7 45 ?? 8C 4C 6F 61

}

condition:
    any of them
}

 

