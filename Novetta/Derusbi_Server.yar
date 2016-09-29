rule Derusbi_Server
{
	meta:
		Author = "Novetta"
		Reference = "http://www.novetta.com/wp-content/uploads/2014/11/Derusbi.pdf"

	strings:
		$uuid = "{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" wide ascii
		$infectionID1 = "-%s-%03d"
		$infectionID2 = "-%03d"
		$other = "ZwLoadDriver"

	condition:
		$uuid or ($infectionID1 and $infectionID2 and $other)
}
