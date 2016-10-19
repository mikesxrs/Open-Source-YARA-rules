rule win_exe_njRAT 
{
meta:
author = "info@fidelissecurity.com"
descripion = "njRAT - Remote Access Trojan"
comment = "Variants have also been observed obfuscated with .NET Reactor"
filetype = "pe"
date = "2013-07-15"
version = "1.0"
hash1 = "92ee1fb5df21d8cfafa2b02b6a25bd3b"
hash2 = "3576d40ce18bb0349f9dfa42b8911c3a"
hash3 = "24cc5b811a7f9591e7f2cb9a818be104"
hash4 = "3ad5fded9d7fdf1c2f6102f4874b2d52"
hash5 = "a98b4c99f64315aac9dd992593830f35"
hash6 ="5fcb5282da1a2a0f053051c8da1686ef"
hash7 = "a669c0da6309a930af16381b18ba2f9d"
hash8 = "79dce17498e1997264346b162b09bde8"
hash9 = "fc96a7e27b1d3dab715b2732d5c86f80"
ref1 = "http://bit.ly/19tlf4s"
ref2 = "http://www.fidelissecurity.com/threatadvisory"
ref3 = "http://www.threatgeek.com/2013/06/fidelis-threat-advisory-1009-njratuncovered.html"
ref4 = "http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered.pdf"

strings:
$magic = "MZ"
$string_setA_1 = "FromBase64String"
$string_setA_2 = "Base64String"
$string_setA_3 = "Connected" wide ascii
$string_setA_4 = "Receive"
$string_setA_5 = "DeleteSubKey" wide ascii
$string_setA_6 = "get_MachineName"
$string_setA_7 = "get_UserName"
$string_setA_8 = "get_LastWriteTime"
$string_setA_9 = "GetVolumeInformation"

$string_setB_1 = "OSFullName" wide ascii
$string_setB_2 = "Send" wide ascii
$string_setB_3 = "Connected" wide ascii
$string_setB_4 = "DownloadData" wide ascii
$string_setB_5 = "netsh firewall" wide
$string_setB_6 = "cmd.exe /k ping 0 & del" wide

condition:
($magic at 0) and ( all of ($string_setA*) or all of ($string_setB*) ) 
}