rule malicious_LNK_files
{
strings:
	$magic = {4C 00 00 00 01 14 02 00} // L.......
	$s1 = "\\RECYCLER\\" wide
	$s2 = "%temp%" wide
	$s3 = "%systemroot%\\system32\\cmd.exe" wide
	//$s4 = "./start" wide
	$s5 = "svchost.exe" wide
	$s6 = "lsass.exe" wide
	$s7 = "csrss.exe" wide
	$s8 = "winlogon.exe" wide
	//$s9 = "%cd%" wide
	$s10 = "%appdata%" wide
	$s11 = "%programdata%" wide
	$s12 = "%localappdata%" wide
	$s13 = ".cpl" wide
condition:
	($magic at 0) and any of ($s*)
}