rule 
remsec_executable_blob_parser
{
meta:
copyright = "Symantec"
strings:
$code =
/*
0F 82 ?? ?? 00 00               jb      l_0
80 7? 04 02                     cmp     byte ptr [r0+4], 2
0F 
85 ?? ?? 00 00               jnz     l_0
81 3? 02 AA 02 C1               cmp     dword ptr [r0], 
0C102AA02h
0F 85 ?? ?? 00 00               jnz     l_0
8B ?? 06                        mov     r1, [r0+6]
*/
{
( 0F 82 ?? ?? 00 00 | 72 ?? )
( 80 | 41 80 ) ( 7? | 7C 24 ) 04 02
( 0F 85 ?? ?? 00 00 | 75 ?? )
( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) 02 AA 02 C1
( 0F 85 ?? ?? 00 00 | 75 ?? )
( 8B | 41 
8B | 44 8B | 45 8B ) ( 4? | 5? | 6? | 7? | ?4 24 | 
?C 24 ) 06
}
condition:
all of them
}