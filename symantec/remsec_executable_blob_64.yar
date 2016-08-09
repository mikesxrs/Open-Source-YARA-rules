rule remsec_executable_blob_64
{
meta:
copyright = "Symantec"
strings:
$code =
/*
31 06                       l0: xor   
[rsi], eax
48 83 C6 04                     add     rsi, 4
D1 E8                           shr     eax, 1
73 05                           jnb     short l1
35 01 00 00 D0                  xor     eax, 0D00000
01h
E2 EF                       l1: loop    l0
*/
{
31 06
48 83 C6 04
D1 E8
73 05
35 01 00 00 D0
E2 EF
}
condition:
all of them
}