import "pe"
rule HermeticWiper_Certificate {
   meta:
      description = "Detects a certificate used in HermeticWiper Attack"
      date = "2022-02-24"
	  author = "@X0RC1SM"
      hash = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
	  malware = "HermeticWiper"
   condition:
      uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_signatures) : (pe.signatures[i].serial == "0c:48:73:28:73:ac:8c:ce:ba:f8:f0:e1:e8:32:9c:ec")
}
