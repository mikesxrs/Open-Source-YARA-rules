rule encoded_vbs
{
	meta:
		author = "Niels Warnars"
		date = "2016/07/31"
		description = "Encoded .vbs detection"
		reference = "https://gallery.technet.microsoft.com/Encode-and-Decode-a-VB-a480d74c"
	strings:
		$begin_tag1 = "#@~^" 
		$begin_tag2 = "=="
		$end_tag = "==^#~@"
	condition:
	   $begin_tag1 at 0 and $begin_tag2 at 10 and $end_tag
}