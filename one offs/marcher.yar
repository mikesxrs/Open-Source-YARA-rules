rule marcher
{
	meta:
		description = "This rule detects a variant of Marcher"
		sample = "6c15fcdcee665dd38a24931da27b1e16c0b15de832d968bf5891d8e389a32d3e"
		author = "strobostro"

	strings:
		$a = "com.note.donote" wide
		$b = "Adobe Flash Player" wide
		$c = "Click on Activate button to secure your application" wide
		$d = "Please submit your Verifed buy MasterCard Password" wide
		$e = "Please submit your Verifed buy Visa Password" wide

	condition:
		$a and any of ($b,$c,$d,$e)

}
