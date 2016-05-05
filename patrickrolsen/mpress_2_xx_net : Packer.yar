rule mpress_2_xx_net : Packer
{
meta:
	author="Kevin Falcoz"
	date_create="24/03/2013"
	description="MPRESS v2.XX .NET"
strings:
	$signature1={21 46 00 69 00 6C 00 65 00 20 00 69 00 73 00 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 2E 00 00 0D 4D 00 50 00 52 00 45 00 53 00 53 00 00 00 00 00 2D 2D 93 6B 35 04 2E 43 85 EF}
condition:
	$signature1
}