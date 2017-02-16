rule IMPLANT_11_v1
{
meta:
	author = "US-CERT"
	description = "MiniDuke"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = {63 74 00 00} // ct
	$STR2 = {72 6F 74 65} // rote
	$STR3 = {75 61 6C 50} // triV
	$STR4 = {56 69 72 74} // Plau
	//$STR5 = { e8 00 00 00 00 }
	$STR6 = { 64 FF 35 00 00 00 00 }
	$STR7 = {D2 C0}
	$STR8 = /\x63\x74\x00\x00.{3,20}\x72\x6F\x74\x65.{3,20}\x75\x61\x6C\x50.{3,20}\x56\x69\x72\x74/

condition:
	(uint16(0) == 0x5A4D) and /*#STR5 > 4 and*/ all of them
}
