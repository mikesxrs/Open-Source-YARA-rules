rule AdGholas_mem
{
 meta:
     malfamily = "AdGholas"
	 author = "Proofpoint"
	 reference = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"
	 reference2 = "https://blog.malwarebytes.com/cybercrime/exploits/2016/12/adgholas-malvertising-business-as-usual/"

 strings:
      $a1 = "(3e8)!=" ascii wide
      $a2 = /href=\x22\.\x22\+[a-z]+\,mimeType\}/ ascii wide
      $a3 = /\+[a-z]+\([\x22\x27]divx[^\x22\x27]+torrent[^\x22\x27]*[\x22\x27]\.split/ ascii wide
      $a4 = "chls" nocase ascii wide
      $a5 = "saz" nocase ascii wide
      $a6 = "flac" nocase ascii wide
      $a7 = "pcap" nocase ascii wide

 condition:
      all of ($a*)
}
