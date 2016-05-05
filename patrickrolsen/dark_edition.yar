rule dark_edition
{
meta:
	author = "@patrickrolsen"
	maltype = "EXE"
	version = "0.1"
	reference = "Dark Edition" 
strings:
	$s1 = "[ Dark Edition ]" wide
condition:
    uint16(0) == 0x5A4D and $s1
}