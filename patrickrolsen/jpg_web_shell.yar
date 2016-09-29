/*
rule jpg_web_shell
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	data = "12/19/2013"
	reference = "http://www.securelist.com/en/blog/208214192/Malware_in_metadata"
strings:
	$magic = { ff d8 ff e? } // e0, e1, e8
	$s1 = "<script src"
	$s2 = "/.*//*e"
	$s3 = "base64_decode"
condition:
	($magic at 0) and 1 of ($s*)
}  
*/