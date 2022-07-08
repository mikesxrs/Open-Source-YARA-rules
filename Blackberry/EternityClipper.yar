import "pe"


rule EternityClipper {
   meta:
      description = "Detects Eternity Clipper"
      reference = "https://blogs.blackberry.com/en/2022/06/threat-spotlight-eternity-project-maas-goes-on-and-on"
      author = "BlackBerry Threat Research Team"
      date = "2022-05-22"
      license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"


   strings:
      $s1 = "CopyFromScreen"
      $s2 = "CaptureDesktop"
      $s3 = "Win32Clipboard"
      $s4 = "Clipboard Manager"
      $s5 = "Eternity.exe" wide
      $s6 = "AddClipboardFormatListener"
      $s7 = "AesCryptoServiceProvider"


   condition:
   (
   //PE File
   uint16(0) == 0x5a4d and

   //All Strings
   all of ($s*) )
}
