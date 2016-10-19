rule CaptainWord {
	meta:
		author = "Alienvault Labs"
		reference = "https://www.alienvault.com/blogs/labs-research/cyber-espionage-campaign-against-the-uyghur-community-targeting-macosx-syst"
		

    strings:

         $header = {D0 CF 11 E0 A1 B1 1A E1}

         $author = {00 00 00 63 61 70 74 61 69 6E 00}

    condition:

         $header at 0 and $author

}