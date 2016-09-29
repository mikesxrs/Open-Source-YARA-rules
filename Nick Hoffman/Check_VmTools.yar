rule Check_VmTools
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmTools reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$tools = "SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide
	condition:
		$tools
}