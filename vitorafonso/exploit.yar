import "androguard"

rule Exploit
{
	meta:
		description = "Detects some exploits"
		author = "vitorafonso"
		sample = "168f82516742a9580fb9d0c907140428f9d3837c88e0b3865002fd221b8154a1"

	strings:
		$a = "Ohh, that's make joke!"
		$b = "CoolXMainActivity"

	condition:
		all of them

}
