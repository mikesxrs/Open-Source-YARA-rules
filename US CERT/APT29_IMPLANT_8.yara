rule IMPLANT_8_v1
{
meta:
	author = "US-CERT"
	description = "APT29  HAMMERTOSS / HammerDuke"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$DOTNET = "mscorlib" ascii
	$REF_URL = "https://www.google.com/url?sa=" wide
	$REF_var_1 = "&rct=" wide
	$REF_var_2 = "&q=&esrc=" wide
	$REF_var_3 = "&source=" wide
	$REF_var_4 = "&cd=" wide
	$REF_var_5 = "&ved=" wide
	$REF_var_6 = "&url=" wide
	$REF_var_7 = "&ei=" wide
	$REF_var_8 = "&usg=" wide
	$REF_var_9 = "&bvm=" wide
	$REF_value_1 = "QFj" wide
	$REF_value_2 = "bv.81" wide

condition:
	(uint16(0) == 0x5A4D) and ($DOTNET) and ($REF_URL) and (3 of ($REF_var*)) and (1 of($REF_value*))
}

rule IMPLANT_8_v2
{
meta:
	author = "US-CERT"
	description = "APT29  HAMMERTOSS / HammerDuke"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$DOTNET= "mscorlib" ascii
	$XOR = {61 20 AA 00 00 00 61}

condition:
	(uint16(0) == 0x5A4D) and all of them
}
