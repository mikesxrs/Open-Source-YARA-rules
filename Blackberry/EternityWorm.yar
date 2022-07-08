import "pe"


rule EternityWorm {
   meta:
      description = "Detects Eternity Worm"
      reference = "https://blogs.blackberry.com/en/2022/06/threat-spotlight-eternity-project-maas-goes-on-and-on"
      author = "BlackBerry Threat Research Team"
      date = "2022-05-22"
      license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"


   strings:
      $s1 = "Eternity 2022" wide
      $s2 = "Eternity" wide
      $s3 = "Anal Worm" wide
      $s4 = "Made in Heaven" wide
      $s5 = "Van Darkholme" wide
      $s6 = "EternityWorm.exe" wide


   condition:
   (
   //PE File
   uint16(0) == 0x5a4d and
   pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and


   //All Strings
   all of ($s*) )
}
