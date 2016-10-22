rule banswift :banswift {
meta:
description = “Yara rule to detect samples that share wiping function with banswift”
threat_level = 10
reference = "https://www.blueliv.com/research/recap-of-cyber-attacks-targeting-swift/"
strings:
$snippet1 = {88 44 24 0D B9 FF 03 00 00 33 C0 8D 7C 24 2D C6 44 24 2C 5F 33 DB F3 AB 66 AB 53 68 80 00 00 00 6A 03 53 AA 8B 84 24 40 10 00 00 53 68 00 00 00 40 50 C6 44 24 2A FF 88 5C 24 2B C6 44 24 2C 7E C6 44 24 2D E7}
/*
88 44 24 0D mov [esp+102Ch+var_101F], al
B9 FF 03 00 00 movecx, 3FFh
33 C0 xoreax, eax
8D 7C 24 2D lea edi, [esp+102Ch+var_FFF]
C6 44 24 2C 5F mov [esp+102Ch+var_1000], 5Fh
33 DB xorebx, ebx
F3 AB rep stosd
66 AB stosw
53 push ebx ; _DWORD
68 80 00 00 00 push 80h ; _DWORD
6A 03 push 3 ; _DWORD
53 push ebx ; _DWORD
AA stosb
8B 84 24 40 10 00 00 moveax, [esp+103Ch+arg_0]
53 push ebx ; _DWORD
68 00 00 00 40 push 40000000h ; _DWORD
50 push eax ; _DWORD
C6 44 24 2A FF mov [esp+1048h+var_101E], 0FFh
88 5C 24 2B mov [esp+1048h+var_101D], bl
C6 44 24 2C 7E mov [esp+1048h+var_101C], 7Eh
C6 44 24 2D E7 mov [esp+1048h+var_101B], 0E7h
*/
$snippet2 = {25 FF 00 00 00 B9 00 04 00 00 8A D0 8D 7C 24 30 8A F2 8B C2 C1 E0 10 66 8B C2 F3 AB}
/*
25 FF 00 00 00 and eax, 0FFh
B9 00 04 00 00 movecx, 400h
8A D0 mov dl, al
8D 7C 24 30 lea edi, [esp+30h]
8A F2 mov dh, dl
8B C2 moveax, edx
C1 E0 10 shleax, 10h
66 8B C2 mov ax, dx
F3 AB rep stosd
*/
condition:
all of ($snippet*)
}