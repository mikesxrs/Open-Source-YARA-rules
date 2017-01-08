rule Hancidoc : Dropper
{
	meta:
		author="moutonplacide"
		date="2016-11-23"
		description="Hancitor document dropper"

	strings:
		$doc = {d0 cf 11 e0 a1 b1 1a e1 00 00} /* DOC Header */
        	$author = "Kimberly"
	        $pe_marker = /[A-Z]{8}\x08\x00/ /*STARFALL / FORTINET marker*/
	condition:
		($doc at 0) and ($author and $pe_marker)
}
