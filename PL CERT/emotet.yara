/*
from https://www.cert.pl/en/news/single/analysis-of-emotet-v4/
*/

rule emotet4_basic: trojan
{
meta:
author = "psrok1/mak"
module = "emotet"
strings:
$emotet4_rsa_public = { 8d ?? ?? 5? 8d ?? ?? 5? 6a 00 68 00 80 00 00 ff 35 [4] ff 35 [4] 6a 13 68 01 00 01 00 ff 15 [4] 85 }
$emotet4_cnc_list = { 39 ?? ?5 [4] 0f 44 ?? (FF | A3)}
condition:
all of them
}

rule emotet4: trojan
{
meta:
author = "psrok1"
module = "emotet"
strings:
$emotet4_x65599 = { 0f b6 ?? 8d ?? ?? 69 ?? 3f 00 01 00 4? 0? ?? 3? ?? 72 }
condition:
any of them and emotet4_basic
}

rule emotet4_spam : spambot
{
meta:
author="mak"
module="emotet"
strings:
$login="LOGIN" fullword
$startls="STARTTLS" fullword
$mailfrom="MAIL FROM:"
condition:
all of them and emotet4_basic
}
