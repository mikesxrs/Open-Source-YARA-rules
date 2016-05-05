rule FE_PCAPs
{
meta:
	author = "@patrickrolsen"
	maltype = "N/A"
	version = "0.1"
	description = "Find FireEye PCAPs uploaded to Virus Total"
	date = "12/30/2013"
strings:
	$magic = {D4 C3 B2 A1}
	$ip1 = {0A 00 00 ?? C7 10 C7 ??} // "10.0.0.?? -> 199.16.199.??
	$ip2 = {C7 10 C7 ?? 0A 00 00 ??} // "199.16.199.?? -> 10.0.0.??"
condition:
	$magic at 0 and all of ($ip*)
}