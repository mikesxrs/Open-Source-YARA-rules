rule AdGholas_mem_antisec_M2
{
 meta:
     malfamily = "AdGholas"
	 author = "Proofpoint"
	 reference = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"
	 reference2 = "https://blog.malwarebytes.com/cybercrime/exploits/2016/12/adgholas-malvertising-business-as-usual/"


 strings:
     $s1 = "ActiveXObject(\"Microsoft.XMLDOM\")" nocase ascii wide
     $s2 = "loadXML" nocase ascii wide fullword
     $s3 = "parseError.errorCode" nocase ascii wide
     $s4 = /res\x3a\x2f\x2f[\x27\x22]\x2b/ nocase ascii wide
     $s5 = /\x251e3\x21\s*\x3d\x3d\s*[a-zA-Z]+\x3f1\x3a0/ nocase ascii wide

 condition:
     all of ($s*)
}
