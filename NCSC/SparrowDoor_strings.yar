rule SparrowDoor_strings {
meta:
author = "NCSC"
description = "Strings that appear in SparrowDoor’s backdoor. Targeting in memory."
reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
date = "2022-02-28"
hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"
strings:
$reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
$http_headers = {55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 35 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 35 2E 30 29 0D 0A 41 63 63 65 70 74 2D 4C 61 6E 67 75 61 67 65 3A 20 65 6E 2D 55 53 0D 0A 41 63 63 65 70 74 3A 20 2A 2F 2A 0D 0A}
$http_proxy = "HTTPS=HTTPS://%s:%d" ascii
$debug = "SeDebugPrivilege" ascii
$av1 = "avp.exe" ascii // Kaspersky
$av2 = "ZhuDongFangYu.exe" ascii // Qihoo360
$av3 = "egui.exe" ascii // ESET
$av4 = "TMBMSRV.exe" ascii // Trend Micro
$av5 = "ccSetMgr.exe" ascii // Norton
$clipshot = "clipshot" ascii
$ComSpec = "ComSpec" ascii
$export = "curl_easy_init" ascii
condition:
10 of them
}
