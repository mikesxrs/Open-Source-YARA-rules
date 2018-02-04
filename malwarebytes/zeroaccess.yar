rule zaccess_3
{
   meta:
      author = "josh"
      reference = "https://blog.malwarebytes.com/threat-analysis/2013/10/using-yara-to-attribute-malware/"
      description = "ZeroAccess Trojan, WaesColaweExport found"
   strings:
      $WaesColaweExport = { 55 8B EC 5? 0F B6 [5] 8A [5] 8? [1-2] 99 0F B6 [1] F7 [1] B? [4] 8? [2] 8? [2] 66 (8B|A1) [4-5] 66 2B [1] 0F B7 [1] (35|83 F0) [1-4] C1 E8 [1-4] 8B E5 5D C2 }
      $interface = "jjjinterface"
   condition:
      all of them
}
