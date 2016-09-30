rule BackdoorDediprosA
{
        meta:
			Description  = "Backdoor.Dedipros.rc"
			ThreatLevel  = "5"

        strings:
            $ = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/advapi32.dll" ascii wide
			$ = "rundll32.exe %s, CodeMain lpServiceName" ascii wide
			$ = "C:\\Windows\\System32\\Rundlla.dll" ascii wide
			$ = "s%\\pmeT\\SWODNIW\\:C" ascii wide
			$ = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii wide
			$ = "\\keylog.dat" ascii wide
        condition:
            2 of them
}