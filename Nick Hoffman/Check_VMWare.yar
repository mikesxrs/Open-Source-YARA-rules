rule Check_VMWare_DeviceMap
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmWare Registry Keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" wide ascii nocase
		$value = "Identifier" wide nocase ascii
		$data = "VMware" wide nocase ascii
	condition:
		all of them
}