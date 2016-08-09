rule remsec_packer_B
{
meta:
copyright = "Symantec"
strings:
$code =
/*
48 8B 05 C4 2D 01 00            mov     rax, cs:LoadLibraryA
48 89 44 24 48                  mov     qword ptr 
[rsp+1B8h+descriptor+18h], rax
48 8B 05 A
0 2D 01 00            mov     rax, cs:GetProcAddress
48 8D 4C 24 30                  lea     rcx, 
[rsp+1B8h+descriptor]
48 89 44 2
4 50                  mov     qword ptr 
[rsp+1B8h+descriptor+20h], rax
48 8D 84 24 80 00 00 00         lea     rax, 
[rsp+1B8h+var_138]
C6 44 24 30 00                  mov     [rsp+1B8h+descriptor], 
0
48 89 44 24 60      
mov     qword ptr 
[rsp+1B8h+descriptor+30h], rax
48 8D 84 24 80 00 00 00         lea     rax, 
[rsp+1B8h+var_138]
C7 44 24 34 03 00 00 00         mov     dword ptr 
[rsp+1B8h+descriptor+4], 3
2B F8             
sub     edi, eax
48 89 5C 24 38                  mov     qword ptr 
[rsp+1B8h+descriptor+8], rbx
44 89 6C 24 40                  mov     dword ptr 
[rsp+1B8h+descriptor+10h], r13d
83 C7 08                    
add     edi, 8
89 7C 24 68                     mov     dword ptr 
[rsp+1B8h+descriptor+38h], edi
FF D5                           call    rbp
05 00 00 00 3A                  add     eax, 3A000000h
*/
{
48 8B 05 ?? ?? ?? ??
48 89 44 24 ??
48 8B 05 ?? ?? ?? ??
48 8D 4C 24 ??
48 89 44 24 ??
48 8D ( 45 ?? | 84 24 ?? ?? 00 00 )
( 44 88 6? 24 ?? | C6 44 24 ?? 00 )
48 89 44 24 ??
48 8D ( 45 ?? | 84 24 ?? ?? 00 00 )
C7 44 24 ?? 0? 00 00 00
2B ?8
48 89 ?C 24 ??
44 89 6? 24 ??
83 C? 08
89 ?C 24 ??
( FF | 41 FF ) D?
( 05 | 8D 88 ) 00 00 00 3A
}
condition:
all of them
}