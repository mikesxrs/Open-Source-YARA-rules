rule Check_VBox_Guest_Additions
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of the guest additions registry key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" wide ascii nocase
	condition:
		any of them	
}