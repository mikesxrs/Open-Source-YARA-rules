
rule viewweb {
	strings:
		$dllstring = "viewweb.dll\x00DllCmd\x00"

	condition:
		IsPeFile and $dllstring
}

