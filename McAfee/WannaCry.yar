rule wannacry_1 : ransom
{
meta:
author = "Joshua Cannell"
description = "WannaCry Ransomware strings"
reference = "https://securingtomorrow.mcafee.com/executive-perspectives/analysis-wannacry-ransomware-outbreak/"
weight = 100
date = "2017-05-12"
 
strings:
$s1 = "Ooops, your files have been encrypted!" wide ascii nocase
$s2 = "Wanna Decryptor" wide ascii nocase
$s3 = ".wcry" wide ascii nocase
$s4 = "WANNACRY" wide ascii nocase
$s5 = "WANACRY!" wide ascii nocase
$s7 = "icacls . /grant Everyone:F /T /C /Q" wide ascii nocase
 
condition:
any of them
}
rule wannacry_2{
meta:
author = "Harold Ogden"
description = "WannaCry Ransomware Strings"
reference = "https://securingtomorrow.mcafee.com/executive-perspectives/analysis-wannacry-ransomware-outbreak/"
date = "2017-05-12"
weight = 100
strings:
$string1 = "msg/m_bulgarian.wnry"
$string2 = "msg/m_chinese (simplified).wnry"
$string3 = "msg/m_chinese (traditional).wnry"
$string4 = "msg/m_croatian.wnry"
$string5 = "msg/m_czech.wnry"
$string6 = "msg/m_danish.wnry"
$string7 = "msg/m_dutch.wnry"
$string8 = "msg/m_english.wnry"
$string9 = "msg/m_filipino.wnry"
$string10 = "msg/m_finnish.wnry"
$string11 = "msg/m_french.wnry"
$string12 = "msg/m_german.wnry"
$string13 = "msg/m_greek.wnry"
$string14 = "msg/m_indonesian.wnry"
$string15 = "msg/m_italian.wnry"
$string16 = "msg/m_japanese.wnry"
$string17 = "msg/m_korean.wnry"
$string18 = "msg/m_latvian.wnry"
$string19 = "msg/m_norwegian.wnry"
$string20 = "msg/m_polish.wnry"
$string21 = "msg/m_portuguese.wnry"
$string22 = "msg/m_romanian.wnry"
$string23 = "msg/m_russian.wnry"
$string24 = "msg/m_slovak.wnry"
$string25 = "msg/m_spanish.wnry"
$string26 = "msg/m_swedish.wnry"
$string27 = "msg/m_turkish.wnry"
$string28 = "msg/m_vietnamese.wnry"
condition:
any of ($string*)
}
