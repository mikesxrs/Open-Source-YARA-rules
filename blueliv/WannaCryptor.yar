rule wannacry_static_ransom : wannacry_static_ransom {

meta:

description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$mutex01 = "Global\\MsWinZonesCacheCounterMutexA" ascii

$lang01 = "m_bulgarian.wnr" ascii

$lang02 = "m_vietnamese.wnry" ascii

$startarg01 = "StartTask" ascii

$startarg02 = "TaskStart" ascii

$startarg03 = "StartSchedule" ascii

$wcry01 = "WanaCrypt0r" ascii wide

$wcry02 = "WANACRY" ascii

$wcry03 = "WANNACRY" ascii

$wcry04 = "WNCRYT" ascii wide

$forig01 = ".wnry\x00" ascii

$fvar01 = ".wry\x00" ascii

condition:

($mutex01 or any of ($lang*)) and ( $forig01 or all of ($fvar*) ) and any of ($wcry*) and any of ($startarg*)

}

rule wannacry_memory_ransom : wannacry_memory_ransom {

meta:

description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants in memory"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$s01 = "%08X.eky"

$s02 = "%08X.pky"

$s03 = "%08X.res"

$s04 = "%08X.dky"

$s05 = "@WanaDecryptor@.exe"

condition:

all of them

}

rule worm_ms17_010 : worm_ms17_010 {

meta:

description = "Detects Worm used during 2017-May-12th WannaCry campaign, which is based on ETERNALBLUE"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$s01 = "__TREEID__PLACEHOLDER__" ascii

$s02 = "__USERID__PLACEHOLDER__@" ascii

$s03 = "SMB3"

$s05 = "SMBu"

$s06 = "SMBs"

$s07 = "SMBr"

$s08 = "%s -m security" ascii

$s09 = "%d.%d.%d.%d"

$payloadwin2000_2195 =

"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00"

$payload2000_50 =

"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"

condition:

all of them

}

