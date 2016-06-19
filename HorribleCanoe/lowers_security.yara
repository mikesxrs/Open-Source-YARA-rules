rule lowers_security {
	strings:
		$actions1 = "EnableLUA"
		$actions2 = "AntiVirusDisableNotify"
		$actions3 = "DisableNotifications"
		$actions4 = "UpdatesDisableNotify"

	condition:
		2 of them
}
