import "pe"

rule _Armadillo_v1xx__v2xx
{
meta:
	description = "Armadillo v1.xx - v2.xx"
strings:
	$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6}
condition:
	$0 at (pe.entry_point)
}
