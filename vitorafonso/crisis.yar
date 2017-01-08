import "androguard"

rule crisis
{
	meta:
		description = "Crisis pack / Hacking team"
		author = "vitorafonso"
		sample = "29b1d89c630d5d44dc3c7842b9da7e29e3e91a644bce593bd6b83bdc9dbd3037"

	strings:
        $a = "background_Tr6871623"

	condition:
		$a and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALLS/) and
		androguard.permission(/android.permission.RECORD_AUDIO/)

}
