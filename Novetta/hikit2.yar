rule hikit2
{
	meta:
		Author = "Novetta"
		Reference = "https://www.novetta.com/wp-content/uploads/2014/11/HiKit.pdf"

	strings:
		$magic1 = {8C 24 24 43 2B 2B 22 13 13 13 00}
		$magic2 = {8A 25 25 42 28 28 20 1C 1C 1C 15 15 15 0E 0E 0E 05 05 05 00}

	condition:
		$magic1 and $magic2
}