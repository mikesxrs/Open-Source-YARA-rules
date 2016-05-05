rule luxnet
{
meta:
	author = "@patrickrolsen"
	maltype = "EXE"
	version = "0.1"
	reference = "Luxnet RAT - http://leak.sx/thread-254973" 
strings:
	$s1 = "XilluX" wide nocase
	$s2 = "Xanity" wide nocase
	$s3 = "PHP RAT Client" wide
condition:
    uint16(0) == 0x5A4D and 1 of ($s*)
}