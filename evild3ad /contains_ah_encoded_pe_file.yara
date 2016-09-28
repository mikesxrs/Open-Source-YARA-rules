import "pe"

rule Contains_ah_encoded_PE_file
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect an &H encoded executable"
		method = "&Hxx is the hexadecimal notation for a byte in VBA"
		reference = "https://blog.didierstevens.com/2014/12/23/oledump-extracting-embedded-exe-from-doc/"
		hash = "6a574342b3e4e44ae624f7606bd60efa"
		date = "2016-04-23"

	strings:
		$MZ = "&H4d&H5a" nocase // DOS header signature in e_magic
		$DOS = "&H21&H54&H68&H69&H73&H20&H70&H72&H6f&H67&H72&H61&H6d&H20&H63&H61&H6e&H6e&H6f&H74&H20&H62&H65&H20&H72&H75&H6e&H20&H69&H6e&H20&H44&H4f&H53&H20&H6d&H6f&H64&H65&H2e" nocase // !This program cannot be run in DOS mode. (DOS stub)
		$PE = "&H50&H45&H00&H00" nocase // PE signature at start of PE header (NtHeader)

	condition:
		$MZ and $DOS and $PE
}