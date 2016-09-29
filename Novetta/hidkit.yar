rule hidkit
{
	meta:
		Author = "Novetta"
		Reference = "https://www.novetta.com/wp-content/uploads/2014/11/HiKit.pdf"

	strings:
		$a = "---HIDE"
		$b = "hide---port = %d"

	condition:
		uint16(0)==0x5A4D and uint32(uint32(0x3c))==0x00004550 and $a and $b
}