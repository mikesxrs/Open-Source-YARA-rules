import "androguard"

rule zitmo
{
	meta:
		description = "Detects Zitmo"
		author = "vitorafonso"
		samples = "d48ce7e9886b293fd5272851407df19f800769ebe4305358e23268ce9e0b8703, e86cdfb035aea4a5cb55efa59a5e68febf2f714525e301b46d99d5e79e02d773"

	strings:
		$a = "REQUEST_SET_ADMIN"
		$b = "RESPONSE_SET_ADMIN"
		$c = "REQUEST_ON"
		$d = "MESSAGE_START_UP"
		$e = "KEY_ADMIN_NUMBER"
		$f = "DEFAULT_ADMIN_NUMBER"

	condition:
		all of them and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/)

}
