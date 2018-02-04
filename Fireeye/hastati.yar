rule Trojan_Hastati
{

meta:

author = "Fireeye"

description = "Korean campaign"

reference = "https://www.fireeye.com/blog/technical/botnet-activities-research/2013/03/more-insights-on-the-recent-korean-cyber-attacks-trojan-hastati.html"


strings:

$str11 = "taskkill /F /IM clisvc.exe" nocase ascii wide

$str2  = "taskkill /F /IM pasvc.exe" nocase ascii wide

$str3  = "shutdown -r -t 0″ nocase ascii wide

condition:

all of them

}
