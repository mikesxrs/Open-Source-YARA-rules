rule remsec_executable_blob_32
{
meta:
copyright = "Symantec"
strings:
$code =
/*
31 06                       l0: xor     [esi], eax
83 C6 04                        add     esi, 4
D1 E8                           shr     eax, 1
73 05              
jnb     short l1
35 01 00 00 D0                  xor     eax, 0D0000001h
E2 F0                       l1: loop    l0
*/
{
31 06
83 C6 04
D1 E8
73 05
35 01 00 00 D0
E2 F0
}
condition:
all of them
}