rule apt3_bemstour_strings
{
meta:

description = "Detects strings used by the Bemstour exploitation tool"
reference = "https://research.checkpoint.com/2019/upsynergy/"
author = "Mark Lechtik"
company = "Check Point Software Technologies LTD."
date = "2019-06-25"
sha256 = "0b28433a2b7993da65e95a45c2adf7bc37edbd2a8db717b85666d6c88140698a"
strings:

$dbg_print_1 = "leaked address is 0x%llx" ascii wide
$dbg_print_2 = "========== %s ==========" ascii wide
$dbg_print_3 = "detailVersion:%d" ascii wide
$dbg_print_4 = "create pipe twice failed" ascii wide
$dbg_print_5 = "WSAStartup function failed with error: %d" ascii wide
$dbg_print_6 = "can't open input file." ascii wide
$dbg_print_7 = "Allocate Buffer Failed." ascii wide
$dbg_print_8 = "Connect to target failed." ascii wide
$dbg_print_9 = "connect successful." ascii wide
$dbg_print_10 = "not supported Platform" ascii wide
$dbg_print_11 = "Wait several seconds." ascii wide
$dbg_print_12 = "not set where to write ListEntry ." ascii wide
$dbg_print_13 = "backdoor not installed." ascii wide
$dbg_print_14 = "REConnect to target failed." ascii wide
$dbg_print_15 = "Construct TreeConnectAndX Request Failed." ascii wide
$dbg_print_16 = "Construct NTCreateAndXRequest  Failed." ascii wide
$dbg_print_17 = "Construct Trans2  Failed." ascii wide
$dbg_print_18 = "Construct ConsWXR  Failed." ascii wide
$dbg_print_19 = "Construct ConsTransSecondary  Failed." ascii wide
$dbg_print_20 = "if you don't want to input password , use server2003 version.." ascii wide

$cmdline_1 = "Command format  %s TargetIp domainname username password 2" ascii wide
$cmdline_2 = "Command format  %s TargetIp domainname username password 1" ascii wide
$cmdline_3 = "cmd.exe /c net user test test /add && cmd.exe /c net localgroup administrators test /add" ascii wide
$cmdline_4 = "hello.exe  \"C:\\WINDOWS\\DEBUG\\test.exe\"" ascii wide
$cmdline_5 = "parameter not right" ascii wide

$smb_param_1 = "browser" ascii wide
$smb_param_2 = "spoolss" ascii wide
$smb_param_3 = "srvsvc" ascii wide
$smb_param_4 = "\\PIPE\\LANMAN" ascii wide
$smb_param_5 = "Werttys for Workgroups 3.1a" ascii wide
$smb_param_6 = "PC NETWORK PROGRAM 1.0" ascii wide
$smb_param_7 = "LANMAN1.0" ascii wide
$smb_param_8 = "LM1.2X002" ascii wide
$smb_param_9 = "LANMAN2.1" ascii wide
$smb_param_10 = "NT LM 0.12" ascii wide
$smb_param_12 = "WORKGROUP" ascii wide
$smb_param_13 = "Windows Server 2003 3790 Service Pack 2" ascii wide
$smb_param_14 = "Windows Server 2003 5.2" ascii wide
$smb_param_15 = "Windows 2002 Service Pack 2 2600" ascii wide
$smb_param_16 = "Windows 2002 5.1" ascii wide
$smb_param_17 = "PC NETWORK PROGRAM 1.0" ascii wide
$smb_param_18 = "Windows 2002 5.1" ascii wide
$smb_param_19 = "Windows for Workgroups 3.1a" ascii wide

$unique_str_1 = "WIN-NGJ7GKNROVS"
$unique_str_2 = "XD-A31C2E0087B2"

condition:
    uint16(0) == 0x5a4d and (5 of ($dbg_print*) or 2 of ($cmdline*) or 1 of ($unique_str*)) and 3 of ($smb_param*)
}

 

 
