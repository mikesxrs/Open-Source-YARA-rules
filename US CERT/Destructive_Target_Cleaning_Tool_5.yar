rule Destructive_Target_Cleaning_Tool_5

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"
	
    strings:
		$MCU_DLL_ZLIB_COMPRESSED2= "{5CECABAE813CC9BCD5A542F454910428343479806F71D5521E2AOD}"

	condition:
		all of them
}

