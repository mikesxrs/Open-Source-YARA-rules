rule APT_DeputyDog_Strings
{

	meta:

		author = "FireEye Labs"
		version = "1.0"
		description = "detects string seen in samples used in 2013-3893 0day attacks"
		reference = "8aba4b5184072f2a50cbc5ecfe326701"

	strings:

		$mz = {4d 5a}
		$a = "DGGYDSYRL"

	condition:

		($mz at 0) and $a

}