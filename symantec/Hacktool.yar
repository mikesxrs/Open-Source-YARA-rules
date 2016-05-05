rule Hacktool
{
 	meta:
 		author = “Symantec Security Response”
 		date = “2015-07-01”
 		description = “Butterfly hacktool”
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

 	strings:
 		$str _ 1 = “\\\\.\\pipe\\winsession” wide
 		$str _ 2 = “WsiSvc” wide
 		$str _ 3 = “ConnectNamedPipe”
 		$str _ 4 = “CreateNamedPipeW”
 		$str _ 5 = “CreateProcessAsUserW”
 		
 	condition:
 		all of them
}