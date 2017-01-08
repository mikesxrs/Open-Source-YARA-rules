rule pax_dll : malware
{
	meta:
		description = "Identify the dll loader of _p.ax/HOMEUNIX/9002"
		author = "tracker [_at] h3x.eu"

	strings:
		$orig_name_1 = "ServiceDll.dll"
		$orig_name_2 = "piDLL.dll"
		$orig_name_3 = "psd.dll"


		$all_s1 = "SetServiceStatus"
		$all_s2 = "RegQueryValueExA"
		$all_s3 = "RegOpenKeyExA"

		//$file_name_1 = "msisvcd.dll"
		//$file_name_2 = "mstisvc.dll"

	condition:
	 	//file_type contains "pe"
		uint16(0) == 0x5a4d and
		any of ( $orig_name_* )
		and all of ( $all_* )
		//and file_name contains ( $file_name_* )
}
