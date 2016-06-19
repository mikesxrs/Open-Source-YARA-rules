private rule MsAttackerStage2 : MsAttacker Family
{
	meta:
		description = "Identifying strings for MsAttacker stage 2"
		last_modified = "2015-03-12"
	strings:
		$ = "MiniJS.dll"
		$ = "%s \"rundll32.exe %s RealService %s\" /f"
		$ = "reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v \"Start Pages\" /f"
		$ = "3111431114311121270018000127001808012700180"
		$ = "Global\\MSAttacker %d"
	condition:
		any of them
}
private rule MsAttackerStage1 : MsAttacker Family
{
	meta:
		description = "Identifying strings for MsAttacker stage 1"
		last_modified = "2015-03-12"

	strings:
		$ = "http://122.10.117.152/download/ms/CryptBase.32.cab"
		$ = "http://122.10.117.152/download/ms/CryptBase.64.cab"
		$ = "http://122.10.117.152/download/ms/MiniJS.dll"
		$ = "MiniJS.dll"
		$ = "%s;new Downloader('%s', '%s').Fire();"
		$ = "rundll32.exe %s RealService %s"
	condition:
		any of them
}

rule MsAttacker : MsAttacker Family {
	condition:
		MsAttackerStage1 or MsAttackerStage2
}