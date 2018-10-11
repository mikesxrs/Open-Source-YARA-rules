rule LUCKYMOUSE_Stolen_CERT
{
  meta:
    author = "mikesxrs"
    description = "Certificate used to sign malware, could result in False positive due to it being legitimate"
    reference = "https://securelist.com/luckymouse-ndisproxy-driver/87914/"

  strings:
	$STR1 = {78 62 07 2d dc 75 9e 5f 6a 61 4b e9 b9 3b d5 21}
	$STR2 = "ShenZhen LeagSoft Technology Co.,Ltd."
    
  condition: 
	all of them
}
