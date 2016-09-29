/*
URL: https://github.com/0pc0deFR/YaraRules
Developpeur: 0pc0deFR (alias Kevin Falcoz)
compiler.yar contient plusieurs gles permettant d'identifier un compilateur
*/
/*
rule visual_basic_5_6 : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="24/02/2013"
		description="Miscrosoft Visual Basic 5.0/6.0"
		
	strings:
		$str1={68 ?? ?? ?? 00 E8 ?? FF FF FF 00 00 ?? 00 00 00 30 00 00 00 ?? 00 00 00 00 00 00 00 [16] 00 00 00 00 00 00 01 00} 
	
	condition:
		$str1 at (pe.entry_point)
}
*/

rule visual_studio_net : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="24/02/2013"
		description="Miscrosoft Visual Studio .NET/C#"
		
	strings:
		$str1={FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00} /*EntryPoint*/
	
	condition:
		$str1 at (pe.entry_point)
}
rule visual_c_plus_plus_6 : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="Miscrosoft Visual C++ 6.0"
		
	strings:
		$str1={55 8B EC 6A FF 68 [3] 00 68 [3] 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC [1] 53 56 57 89 65 E8} /*EntryPoint*/
	
	condition:
		$str1 at (pe.entry_point)
}
rule visual_c_plus_plus_6_sp : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="Miscrosoft Visual C++ 6.0 SPx"
		
	strings:
		$str1={55 8B EC 83 EC 44 56 FF 15 ?? 10 40 00 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E} /*EntryPoint*/
	
	condition:
		$str1 at (pe.entry_point)
}
rule visual_c_plus_plus_7 : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="Miscrosoft Visual C++ 7.0"
		
	strings:
		$str1={6A 60 68 [2] 40 00 E8 [2] 00 00 BF 94 00 00 00 8B C7 E8 [4] 89 65 E8 8B F4 89 3E 56 FF 15 [2] 40 00 8B 4E 10 89 0D} /*EntryPoint*/
		$str2={6A 0C 68 [4] E8 [4] 33 C0 40 89 45 E4}
	
	condition:
		$str1 at (pe.entry_point) or $str2 at (pe.entry_point)
}
rule borland_delphi_6_7 : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="Borland Delphi 6.0 - 7.0"
		
	strings:
		$str1={55 8B EC 83 C4 F0 53 B8 [3] 00 E8 [3] FF 8B 1D [3] 00 8B 03 BA [2] 52 00 E8 [2] F6 FF B8 [2] 52 00 E8 [2] FF FF 8B 03 E8} /*EntryPoint*/
		$str2={55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 [0-1] 53 [9-11] FF 33 C0 55 68 [3] 00 64 FF 30 64 89 20} /*EntryPoint*/
	
	condition:
		$str1 at (pe.entry_point) or $str2 at (pe.entry_point)
}
