rule InceptionDLL
{
    meta:
author = "Blue Coat Systems, Inc"
info = "Used by unknown APT actors: Inception"
reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    strings:
$a = "dll.polymorphed.dll"
$b = {83 7d 08 00 0f 84 cf 00 00 00 83 7d 0c 00 0f 84 
c5 00 00 00 83 7d 10 00 0f 84 bb 00 00 00 83 7d 14 08 
0f 82 b1 00 00 00 c7 45 fc 00 00 00 00 8b 45 10 89 45 
dc 68 00 00}
$c = {FF 15 ?? ?? ?? ?? 8B 4D 08 8B 11 C7 42 14 00 00 
00 00 8B 45 08 8B 08 8B 55 14 89 51 18 8B 45 08 8B 08 
8B 55 0C 89 51 1C 8B 45 08 8B 08 8B 55 10 89 51 20 8B 
45 08 8B 08}
$d = {68 10 27 00 00 FF 15 ?? ?? ?? ?? 83 7D CC 0A 0F 
8D 47 01 00 00 83 7D D0 00 0F 85 3D 01 00 00 6A 20 6A 
00 8D 4D D4 51 E8 ?? ?? ?? ?? 83 C4 0C 8B 55 08 89 55 
E8 C7 45 D8}  
$e = {55 8B EC 8B 45 08 8B 88 AC 23 03 00 51 8B 55 0C 
52 8B 45 0C 8B 48 04 FF D1 83 C4 08 8B 55 08 8B 82 14 
BB 03 00 50 8B 4D 0C 51 8B 55 0C 8B 42 04}
    condition:
any of them
}