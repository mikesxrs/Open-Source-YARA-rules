// Source: http://yara.readthedocs.org/en/v3.4.0/writingrules.html#conditions
private rule ft_strict_exe
{
  condition:
     // MZ signature at offset 0 and ...
     uint16(0) == 0x5A4D and
     // ... PE signature at offset stored in MZ header at 0x3C
     uint32(uint32(0x3C)) == 0x00004550
}

/*
Example target...
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000020  20 20 20 20 00 00 00 00  00 00 00 00 00 00 00 00  |    ............|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 01 00 00  |................|
00000040  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000080  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000a0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000100  50 45 00 00 4c 01 03 00  bc 7c b1 47 00 00 00 00  |PE..L....|.G....|
00000110  00 00 00 00 e0 00 0f 01  0b 01 07 04 00 e0 00 00  |................|
*/

rule misc_no_dosmode_header : suspicious
{
    meta:
        author = "Jason Batchelor"
        created = "2016-03-02"
        modified = "2016-03-02"
        university = "Carnegie Mellon University"
        description = "Detect on absence of 'DOS Mode' heaader between MZ and PE boundries"

    strings:
        $dosmode = "This program cannot be run in DOS mode."

    condition:
        // (0 .. (uint32(0x3C))) = between end of MZ and start of PE headers
        // 0x3C = e_lfanew = offset of PE header
        ft_strict_exe and not $dosmode in (0x3C .. (uint32(0x3C)))
}


