rule network_traffic_njRAT 
{
meta:
author = "info@fidelissecurity.com"
descripion = "njRAT - Remote Access Trojan"
comment = "Rule to alert on network traffic indicators"
filetype = "PCAP - Network Traffic"
date = "2013-07-15"
version = "1.0"
hash1 = "92ee1fb5df21d8cfafa2b02b6a25bd3b"
hash2 ="3576d40ce18bb0349f9dfa42b8911c3a"
hash3 ="24cc5b811a7f9591e7f2cb9a818be104"
hash4 = "3ad5fded9d7fdf1c2f6102f4874b2d52"
hash5 = "a98b4c99f64315aac9dd992593830f35"
hash6 = "5fcb5282da1a2a0f053051c8da1686ef"
hash7 = "a669c0da6309a930af16381b18ba2f9d"
hash8 = "79dce17498e1997264346b162b09bde8"
hash9 = "fc96a7e27b1d3dab715b2732d5c86f80"
ref1 = "http://bit.ly/19tlf4s"
ref2 = "http://www.fidelissecurity.com/threatadvisory"
ref3 = "http://www.threatgeek.com/2013/06/fidelis-threat-advisory-1009-njrat-uncovered.html"
ref4 = "http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered.pdf"

strings:
$string1 = "FM|'|'|"     // File Manager
$string2 = "nd|'|'|"     // File Manager
$string3 = "rn|'|'|"      // Run File
$string4 = "sc~|'|'|"     // Remote Desktop
$string5 = "scPK|'|'|"     // Remote Desktop
$string6 = "CAM|'|'|"     // Remote Cam
$string7 = "USB Video Device[endof]" // Remote Cam
$string8 = "rs|'|'|"     // Reverse Shell
$string9 = "proc|'|'|"     // Process Manager
$string10 = "k|'|'|"     // Process Manager
$string11 = "RG|'|'|~|'|'|"    // Registry Manipulation
$string12 = "kl|'|'|"     // Keylogger file
$string13 = "ret|'|'|"     // Get Browser Passwords
$string14 = "pl|'|'|"     // Get Browser Passwords
$string15 = "lv|'|'|"     // General
$string16 = "prof|'|'|~|'|'|"   // Server rename
$string17 = "un|'|'|~[endof]"   // Uninstall
$idle_string = "P[endof]"    // Idle Connection

condition:
any of ($string*) or #idle_string > 4  

}