rule _UPX_V200V290
{
meta:
	description = "UPX V2.00-V2.90 -> Markus Oberhumer & Laszlo Molnar & John Reiser"
strings:
	$0 = {FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9}
condition:
	$0
}