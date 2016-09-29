rule compiled_autoit {
	strings:
		$str1 = "This is a compiled AutoIt script. AV researchers please email avsupport@autoitscript.com for support."

	condition:
		all of them
}