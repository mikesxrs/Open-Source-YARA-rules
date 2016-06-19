rule ejects_cdrom {
	strings:
		$cddoor1 = "mciSendString"
		$cddoor2 = "set cdaudio door open"
		$cddoor3 = "set cdaudio door closed"

	condition:
		2 of them
}
