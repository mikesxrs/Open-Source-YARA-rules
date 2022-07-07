rule Powershell_Downloader_POWERGAP {
    meta:
        description = "Detects POWERGAP downloader used against Ukrainian ICS"
        reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
        author = "mmuir@cadosecurity.com"
        date = "2022-04-12"
        license = "Apache License 2.0"
    strings:
        $a = "Start-work" ascii
        $b = "$GpoGuid" ascii
        $c = "$SourceFile" ascii
        $d = "$DestinationFile" ascii
        $e = "$appName" ascii
	$f = "LDAP://ROOTDSE" ascii
	$g = "GPT.INI" ascii
	$h = "Get-WmiObject" ascii
    condition:
        5 of them
}
