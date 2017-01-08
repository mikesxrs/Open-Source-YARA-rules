rule bookworm_dll_by_name : malware
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Match ushata by the name"

	strings:
		$dll01 = "ushata.dll"
		$dll02 = "XecureIO_v20.dll"

	condition:
		any of them 
		and filesize < 10000

}


rule bookworm_dll_by_signature : malware
{
	 meta:
		 author = "@h3x2b <tracker _AT h3x.eu>"
		 description = "Detect bookworm.dll loader"

	 strings:
		 $a = { 80 34 18 58 }
		 $b = { 80 34 18 78 }
		 $c = { 80 34 18 D0 }

	 condition:
		 all of them
}


rule bookworm_payload_by_modules_names : malware
{
	meta:
		 description = "Detect ushata payload by usage of more than 2 modules"
		 author = "@h3x2b <tracker _AT h3x.eu>"

	strings:
		$mod_01 = "Leader.dll"
		$mod_02 = "Coder.dll"
		$mod_03 = "Digest.dll"
		$mod_04 = "AES.dll"
		$mod_05 = "KBLogger.dll"
		$mod_06 = "Network.dll"
		$mod_07 = "Resolver.dll"
		$mod_08 = "HTTP.dll"
		$mod_09 = "WinINetwork.dll"
		$mod_10 = "ushata.dll"
		$mod_11 = "ProgramStartup"

	condition:
		3 of them

}

rule bookworm_payload_match : malware
{
	meta:
		 description = "Detect bookworm payload by encrypted header"
		 author = "@h3x2b <tracker _AT h3x.eu>"

	strings:
		$bookworm_payload_01 = { b0 78 58 d0 58 20 01 fd 0d 68 68 d0 5d 28 48 e0 58 28 3c 71 68 78 58 d0 }

	condition:
		1 of them
}
