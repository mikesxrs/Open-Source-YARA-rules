rule port_forward_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Port Forwarding Tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "%d.%d.%d.%d"
	$s2 = "%i.%i.%i.%i on port %i"
	$s3 = "connect to %s:%i"
	$s4 = "%s:%i established"
	$s5 = "%s:%i closed"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}
