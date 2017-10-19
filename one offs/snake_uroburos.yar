rule snake_packed
{
meta:
author = "artemonsecurity"
md5 = "f4f192004df1a4723cb9a8b4a9eb2fbf"
reference = "http://artemonsecurity.com/uroburos.pdf"
strings:
/*
25 FF FF FE FF and eax, 0FFFEFFFFh
0F 22 C0 mov cr0, eax
C0 E8 ?? ?? 00 00 call sub_????
*/
$cr0 = { 25 FF FF FE FF 0F 22 C0 E8 ?? ?? 00 00}
condition:
any of them
}

rule snake
{
meta:
author = "artemonsecurity"
md5 = "40aa66d9600d82e6c814b5307c137be5"
reference = "http://artemonsecurity.com/uroburos.pdf"
strings:
$ModuleStart = { 00 4D 6F 64 75 6C 65 53 74 61 72 74 00 }
$ModuleStop = { 00 4D 6F 64 75 6C 65 53 74 6F 70 00}
$firefox = "firefox.exe"
condition:
all of them
}
