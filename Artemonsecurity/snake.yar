rule snake
{
meta:
author = "artemon security"
md5 = "40aa66d9600d82e6c814b5307c137be5"
reference = "http://artemonsecurity.com/uroburos.pdf"
strings:
$ModuleStart = { 00 4D 6F 64 75 6C 65 53 74 61 72 74 00 }
$ModuleStop = { 00 4D 6F 64 75 6C 65 53 74 6F 70 00}
$firefox = "firefox.exe"
condition:
all of them
}
