rule Mirage_APT_Backdoor : APT Mirage Backdoor Rat MirageRat
{
    meta:
      author = "Silas Cutler (SCutler@SecureWorks.com)"
      version = "1.0"
      description = "Malware related to APT campaign"
      type = "APT Trojan / RAT / Backdoor"
      reference = "https://www.secureworks.com/research/the-mirage-campaign"

    strings:
      $a1 = "welcome to the desert of the real"
      $a2 = "Mirage"
      $b = "Encoding: gzip"
      $c = /\/[A-Za-z]*\?hl=en/
      
    condition: 
      (($a1 or $a2) or $b) and $c
}