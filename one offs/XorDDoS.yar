rule XorDDoSv1
{
meta:
	author = "Akamai SIRT"
	description = "Rule to detect XorDDoS infection"
	reference = "https://www.akamai.com/us/en/multimedia/documents/state-of-the-internet/fast-dns-xor-botnet-case-study.pdf"
strings:
	$st0 = "BB2FA36AAA9541F0"
	$st1 = "md5="
	$st2 = "denyip="
	$st3 = "filename="
	$st4 = "rmfile="
	$st5 = "exec_packet"
	$st6 = "build_iphdr"
condition:
	all of them
}
