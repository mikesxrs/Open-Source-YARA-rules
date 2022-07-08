rule Unpacker_Stub
{
meta:
  author = "Malware Utkonos"
  date = "2020-12-30"
  description = "First Byte in decoded unpacker stub"
  exemplar = "c1d31fa7484170247564e89c97cc325d1f317fb8c8efe50e4d126c7881adf499"
  reference = "https://blog.reversinglabs.com/blog/code-reuse-across-packers-and-dll-loaders"
strings:
$a = {E8 00 00 00 00 5B 81 EB [4] 8D 83 [4] 89 83 [4] 8D B3 [4] 89 B3 [4] 8B 46 ?? 89 83 [4] 8D B3 [4] 56 8D B3 [4] 56 6A ?? 68 [4] 8D BB [4] FF D7}
condition:
(uint16(0) == 0x5A4D and uint32 (uint32(0x3C)) == 0x00004550) and $a
}
