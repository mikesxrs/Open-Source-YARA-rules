rule CoreFlood_ldr_strings
{
  meta:
 author = "Brian Baskin"
 date = "13 Feb 14"
 comment = "CoreFlood Trojan Loader Strings"
 reference = "http://www.ghettoforensics.com/2014/02/malware-with-no-strings-attached-part-2.html"

  strings:
 $RegKey = "MlLrqtuhA3x0WmjwNM27"
 $API = "3etProcAddr"

  condition:
 all of them
}

rule CoreFlood_ldr_decoder
{
  meta:
 author = "Brian Baskin"
 date = "13 Feb 14"
 comment = "CoreFlood? Trojan Loader Decoding Keys"
 reference = "http://www.ghettoforensics.com/2014/02/malware-with-no-strings-attached-part-2.html"

  strings:
 $Sub_85BA = { 81 EA BA 85 00 00 }
 $XOR_85BC= { 05 BC 85 00 00 }

  condition:
 all of them
}
