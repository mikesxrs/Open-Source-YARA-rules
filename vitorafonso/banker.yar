import "androguard"

rule Banker
{
	meta:
		description = "Detects a Banker"
		author = "vitorafonso"
		sample = "e5df30b41b0c50594c2b77c1d5d6916a9ce925f792c563f692426c2d50aa2524"
		report = "https://blog.fortinet.com/2016/11/01/android-banking-malware-masquerades-as-flash-player-targeting-large-banks-and-popular-social-media-apps"

	strings:
		$a1 = "kill_on"
		$a2 = "intercept_down"
		$a3 = "send_sms"
		$a4 = "check_manager_status"
		$a5 = "browserappsupdate"
		$a6 = "YnJvd3NlcmFwcHN1cGRhdGU=" // browserappsupdate
		$a7 = "browserrestart"
		$a8 = "YnJvd3NlcnJlc3RhcnQ=" // browserrestart
		$a9 = "setMobileDataEnabled"
		$a10 = "adminPhone"

	condition:
		8 of ($a*)

}

rule Acecard
{
	meta:
		description = "Detects some acecard samples"
		author = "vitorafonso"
		sample = "0973da0f5cc7e4570659174612a650f3dbd93b3545f07bcc8b438af09dc257a9"
		report = "https://securelist.com/blog/research/73777/the-evolution-of-acecard/"

	strings:
		$a = "#control_number"
		$b = "client number"
		$c = "INTERCEPTING_INCOMING_ENABLED"
		$d = "#intercept_sms_start"
		$e = "#intercept_sms_stop"
		$f = "intercepted incoming sms"

	condition:
		all of them
}

rule Acecard2
{
	meta:
		description = "Detects some acecard samples"
		author = "vitorafonso"
		sample = "88c744e563f7637e5630cb9b01cad663033ce2861cf01100f6c4e6fbb3e56df9"
		report = "https://securelist.com/blog/research/73777/the-evolution-of-acecard/"

	strings:
		$a = "Internet password"
		$b = "Security no."
		$c = "Keep your Internet Banking and secret authorisation code (SMS) secret. Don't reveal these details to anyone, not even if they claim to be NAB."
		$d = "TYPE_INSTALLED_APPS"
		$e = "TYPE_INTERCEPTED_INCOMING_SMS"
		$f = "TYPE_LISTENED_INCOMING_SMS"
		$g = "TYPE_CONTROL_NUMBER_DATA"

	condition:
		all of them and
		androguard.permission(/android.permission.RECEIVE_SMS/)
}
