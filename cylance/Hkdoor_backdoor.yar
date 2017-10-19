import "pe"

rule hkdoor_backdoor {
   meta:
      author = "Cylance"
      description = "Hacker's Door Backdoor"
      reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"


   strings:
      $s1 = "http://www.yythac.com" fullword ascii
      $s2 = "Example:%s 192.168.1.100 139 -p yyt_hac -t 1" fullword ascii
      $s3 = "password-----------The hacker's door's password" fullword ascii
      $s4 = "It is the client of hacker's door %d.%d public version" fullword ascii
      $s5 = "hkdoordll.dll" fullword ascii
      $s6 = "http://www.yythac.com/images/mm.jpg" fullword ascii
      $s7 = "I'mhackeryythac1977" fullword ascii
      $s8 = "yythac.yeah.net" fullword ascii

   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 4 of ($s*) )
}
