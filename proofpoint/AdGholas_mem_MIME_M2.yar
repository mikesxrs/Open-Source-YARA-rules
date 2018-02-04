rule AdGholas_mem_MIME_M2
{
 meta:
     malfamily = "AdGholas"
	 author = "Proofpoint"
	 reference = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"
	 reference2 = "https://blog.malwarebytes.com/cybercrime/exploits/2016/12/adgholas-malvertising-business-as-usual/"


 strings:
     $s1 = "halog" nocase ascii wide fullword
     $s2 = "pcap" nocase ascii wide fullword
     $s3 = "saz" nocase ascii wide fullword
     $s4 = "chls" nocase ascii wide fullword
     $s5 = /return[^\x3b\x7d\n]+href\s*=\s*[\x22\x27]\x2e[\x27\x22]\s*\+\s*[^\x3b\x7d\n]+\s*,\s*[^\x3b\x7d\n]+\.mimeType/ nocase ascii wide
     $s6 = /\x21==[a-zA-Z]+\x3f\x210\x3a\x211/ nocase ascii wide

 condition:
     all of ($s*)
}
