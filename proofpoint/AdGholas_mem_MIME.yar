rule AdGholas_mem_MIME
{
 meta:
     malfamily = "AdGholas"
	 author = "Proofpoint"
	 reference = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"
	 reference2 = "https://blog.malwarebytes.com/cybercrime/exploits/2016/12/adgholas-malvertising-business-as-usual/"

 strings:
      $b1=".300000000" ascii nocase wide fullword
      $b2=".saz" ascii nocase wide fullword
      $b3=".py" ascii nocase wide fullword
      $b4=".pcap" ascii nocase wide fullword
      $b5=".chls" ascii nocase wide fullword

 condition:
      all of ($b*)
}
