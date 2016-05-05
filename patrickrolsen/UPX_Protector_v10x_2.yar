rule _UPX_Protector_v10x_2
{
meta:
	description = "UPX Protector v1.0x (2)"
strings:
	$0 = {EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB}
condition:
	$0
}