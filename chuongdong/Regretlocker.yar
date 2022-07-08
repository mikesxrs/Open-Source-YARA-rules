rule regretlocker {
	meta:
		description = "YARA rule for RegretLocker"
		reference = "http://chuongdong.com/reverse%20engineering/2020/11/17/RegretLocker/"
		author = "@cPeterr"
		tlp = "white"
	strings:
		$str1 = "tor-lib.dll"
		$str2 = "http://regretzjibibtcgb.onion/input"
		$str3 = ".mouse"
		$cmd1 = "taskkill /F /IM \\"
		$cmd2 = "wmic SHADOWCOPY DELETE"
		$cmd3 = "wbadmin DELETE SYSTEMSTATEBACKUP"
		$cmd4 = "bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures"
		$cmd5 = "bcdedit.exe / set{ default } recoveryenabled No"
		$func1 = "open_virtual_drive()"
		$func2 = "smb_scanner()"
		$checklarge = { 81 fe 00 00 40 06 }
	condition:
		all of ($str*) and any of ($cmd*) and any of ($func*) and $checklarge
}
