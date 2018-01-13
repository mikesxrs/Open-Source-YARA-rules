import "pe"
rule cracked_loki
{
meta:
 	author = "TrendMicro"
  reference = "https://documents.trendmicro.com/assets/appendix-CVE-2017-11882-exploited-to-deliver-a-cracked-version-of-the-loki-infostealer.pdf"
strings:
 	$header = "MZ"
 	$banner = "Fuckav.ru"
 	$aPLib = "aPLib v1.01 - the smaller the better :)"
 	$dot_x_code_start = {60 90 90 90 90 90 90 FF 74 24 24 5F 90 90 90 90 90 90 90 90 90 90}
 	$dot_x_code_xor = {BB FF FF DF DD BE 74 00 ?? ?? 90 90 90 90 30 1E 46 90 90 90 90 80 3E 00}
condition:
 	$header at 0 and $banner and $aPLib and
 	pe.number_of_sections == 4 and
 	pe.sections[3].name == ".x" and
 	pe.sections[3].virtual_address == 0xA0000 and
 	$dot_x_code_start and $dot_x_code_xor
}
