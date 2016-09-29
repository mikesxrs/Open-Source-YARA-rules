rule Check_VBox_Description
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks Vbox description reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "SystemBiosVersion" nocase wide ascii
		$data = "VBOX" nocase wide ascii		
	condition:
		all of them
}