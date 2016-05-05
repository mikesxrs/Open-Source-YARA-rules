rule Multipurpose
{
 	meta:
 		author = “Symantec Security Response”
 		date = “2015-07-01”
 		description = “Butterfly Multipurpose hacktool”
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings:
 		$str _ 1 = “dump %d|%d|%d|%d|%d|%d|%s|%d”
 		$str _ 2 = “kerberos%d.dll”
 		$str _ 3 = “\\\\.\\pipe\\lsassp”
 		$str _ 4 = “pth <PID:USER:DOMAIN:NTLM>: change”
 	condition:
 		all of them
}