rule Qadars_DGA
 {
     meta:
        author = "PhishLabs"
        reference = "https://info.phishlabs.com/blog/dissecting-the-qadars-banking-trojan"
     strings:
         $dga_function = { 69 C9 93 B1 39 3E BE F1 E1 00 00 2B F1 81 E6 FF FF FF 7F B8 56 55 55 55 F7 EE 8B C2 C1 E8 1F 03 C2 8D 04 40 }
      condition:
         $dga_function
 }
