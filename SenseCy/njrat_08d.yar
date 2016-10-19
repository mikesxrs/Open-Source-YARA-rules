rule njrat_08d
{
meta:
	author = “SenseCy”
	date = “23-12-2015”
	description = “Njrat v0.8d”
	reference = "https://blog.sensecy.com/2016/01/05/is-there-a-new-njrat-out-there/"
	sample_filetype = “exe”

strings:
	$string0 = “U0VFX01BU0tfTk9aT05FQ0hFQ0tT” wide
	$string1 = “netsh firewall delete allowedprogram” wide
	$string2 = “netsh firewall add allowedprogram” wide
	$string3 = “cmd.exe /k ping 0 & del” wide
	$string4 = “&explorer /root,\”%CD%” wide
	$string5 = “WScript.Shell” wide
	$string6 = “Microsoft.VisualBasic.CompilerServices”
	$string7 = “_CorExeMain”
	$string8 = { 6d 73 63 6f 72 65 65 2e 64 6c 6c }

condition:
	all of them
}