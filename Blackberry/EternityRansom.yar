import "pe"


rule EternityRansom {
   meta:
      description = "Detects Eternity Ransomware"
      reference = "https://blogs.blackberry.com/en/2022/06/threat-spotlight-eternity-project-maas-goes-on-and-on"
      author = "BlackBerry Threat Research Team"
      date = "2022-05-22"
      license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"


   strings:
      $s1 = "The harddisks of your computer have been encrypted with an Military grade encryption algorithm."
      $s2 = "by Eternity group"
      $s3 = "Eternity"
      $s4 = "decryption_password"
      $s5 = "Povlsomware"
 

   condition:
   (
   //PE File
   uint16(0) == 0x5a4d and

   //All Strings
   all of ($s*) )
}
