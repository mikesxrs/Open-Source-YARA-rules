rule archive_cab : info archive cab windows
{
	meta:
		//author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect CAB archive"

	condition:
                //MSCF on the beginning of file
                uint32(0) == 0x4643534d and
                uint32(1) == 0x00000000 
}

rule embedded_archive_cab : info embedded archive cab windows
{
	meta:
		//author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect CAB archive"

	strings:
		$mscf_h3xstring = { 4D 53 43 46 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 }

	condition:
                //MSCF on the beginning of cab file foolowed by resered zeroes
		$mscf_h3xstring
}
