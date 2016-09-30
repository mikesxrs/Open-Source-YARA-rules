rule TrojanDllpatcherA
{
   meta:
       Description = "Trojan.Dllpatcher.vb"
       ThreatLevel = "5"

   strings:
		$str1 = "Global\\Matil da"  ascii wide
		$str2 = "Global\\Nople Mento"  ascii wide
		$str3 = "%s\\System32\\dnsapi.dll"  ascii wide
		$str4 = "%s\\SysWOW64\\dnsapi.dll"  ascii wide

   condition:
      3 of them
}
