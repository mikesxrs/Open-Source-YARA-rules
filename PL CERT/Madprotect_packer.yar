rule MadProtect : packer {
meta:
 author = "mak" 
 reference = "https://www.cert.pl/en/news/single/madprotect-not-that-mad/"
 strings: 
 $enc_hdr = { 23 59 90 70 e9 c1 ec 82 b4 87 b3 4e 03 10 6c 2e} 
 $key_loop0 = { B0 0F 88 01 04 02 41 3C 4F 72 F7 } 
 $key_loop1 = { B0 0F EB 02 [2] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop2 = { B0 0F EB 03 [3] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop3 = { B0 0F EB 04 [4] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop4 = { B0 0F EB 05 [5] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop5 = { B0 0F EB 06 [6] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop6 = { B0 0F EB 07 [7] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop7 = { B0 0F EB 08 [8] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop8 = { B0 0F EB 09 [9] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop9 = { B0 0F EB 0a [10] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop10 = { B0 0F EB 0b [11] 01 04 02 41 3C 4F 72 F7 } 
 $key_loop11 = { B0 0F EB 0c C? 4F 72 F7 } 
 $key_loop12 = { B0 0F EB 0d C? 4F 72 F7 } 
 $key_loop13 = { B0 0F EB 0e C? 4F 72 F7 } 
 $key_loop14 = { B0 0F EB 0f C? 4F 72 F7 } 
 $pdb = "C:\\Users\\prick\\Documents\\Visual Studio 2010\\Projects\\MadProtect\\Release\\MadProtect.pdb" fullword nocase 
 $s0 = "CoInitializeEx failed: %x" fullword 
 $s1 = "CoInitializeSecurity failed: %x" fullword 
condition: 
 $enc_hdr or (1 of ($key_loop*)) and (1 of ($s*) or $pdb)
 }
