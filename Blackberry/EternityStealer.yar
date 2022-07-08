import "pe"
 

rule EternityStealer {
   meta:
      description = "Detects Eternity Stealer"
      reference = "https://blogs.blackberry.com/en/2022/06/threat-spotlight-eternity-project-maas-goes-on-and-on"
      author = "BlackBerry Threat Research Team"
      date = "2022-05-22"
      license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

   strings:
      $s1 = "Corrupting Growtopia.." wide
      $s2 = "growtopia1.com" wide
      $s3 = "Deleting previous file from startup and copying new one." wide
      $s4 = "Debug mode, dont share this stealer anywhere." wide
      $s5 = "Sending info to Eternity.." wide
      $s6 = "Taking and uploading screenshot.." wide
      $s7 = "dcd.exe" wide
      $s8 = "https://eterprx.net" wide
      $s9 = "https://eternitypr.net" wide

   condition:
   (
   //PE File
   uint16(0) == 0x5a4d and

   pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and

   //All Strings
   all of ($s*) )
}
