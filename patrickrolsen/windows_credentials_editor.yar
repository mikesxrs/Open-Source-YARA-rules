rule windows_credentials_editor
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.ampliasecurity.com/research/wce12_uba_ampliasecurity_eng.pdf"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "NTLMCredentials"
	$s2 = "%d kerberos"
	$s3 = "WCE" nocase
	$s4 = "LSASS.EXE" nocase
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}