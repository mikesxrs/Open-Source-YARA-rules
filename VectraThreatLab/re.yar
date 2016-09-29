rule anti_dbg {
    meta:
        author = "x0r"
        description = "Checks if being debugged"
    version = "0.2"
    strings:
        $d1 = "Kernel32.dll" nocase
        $c1 = "CheckRemoteDebuggerPresent" 
        $c2 = "IsDebuggerPresent" 
        $c3 = "OutputDebugString" 
        $c4 = "ContinueDebugEvent" 
        $c5 = "DebugActiveProcess" 
    condition:
        $d1 and 1 of ($c*)
}

rule anti_dbgtools {
    meta:
        author = "x0r"
        description = "Checks for the presence of known debug tools"
    version = "0.1"
    strings:
        $f1 = "procexp.exe" nocase
        $f2 = "procmon.exe" nocase
        $f3 = "processmonitor.exe" nocase
        $f4 = "wireshark.exe" nocase
        $f5 = "fiddler.exe" nocase
        $f6 = "windbg.exe" nocase
        $f7 = "ollydbg.exe" nocase
        $f8 = "winhex.exe" nocase       
        $f9 = "processhacker.exe" nocase
        $f10 = "hiew32.exe" nocase
        $c11 = "\\\\.\\NTICE" 
        $c12 = "\\\\.\\SICE" 
        $c13 = "\\\\.\\Syser" 
        $c14 = "\\\\.\\SyserBoot" 
        $c15 = "\\\\.\\SyserDbgMsg" 
    condition:
        any of them
}

rule av_sinkhole {
    meta:
        author = "x0r"
        description = "Check for known IP belonging to AV sinkhole"
        version = "0.1"
    strings:
        $s1 = "23.92.16.214"
        $s2 = "23.92.24.20"
        $s3 = "23.239.17.167"
        $s4 = "23.239.18.116"
        $s5 = "50.56.177.56"
        $s6 = "50.57.148.87"
        $s7 = "69.55.59.73"
        $s8 = "82.196.15.88"
        $s9 = "85.159.211.119"
        $s10 = "95.85.23.126"
        $s11 = "96.126.112.224"
        $s12 = "107.170.43.224"
        $s13 = "107.170.106.77"
        $s14 = "107.170.106.95"
        $s15 = "107.170.113.230"
        $s16 = "107.170.122.37"
        $s17 = "107.170.164.115"
        $s18 = "128.199.180.131"
        $s19 = "128.199.187.239"
        $s20 = "143.215.15.2"
        $s21 = "143.215.130.33"
        $s22 = "143.215.130.36"
        $s23 = "143.215.130.38"
        $s24 = "143.215.130.42"
        $s25 = "143.215.130.46"
        $s26 = "162.243.26.100"
        $s27 = "162.243.90.135"
        $s28 = "162.243.106.156"
        $s29 = "162.243.106.160"
        $s30 = "162.243.106.165"
        $s31 = "166.78.16.123"
        $s32 = "166.78.158.73"
        $s33 = "192.241.129.22"
        $s34 = "192.241.142.145"
        $s35 = "192.241.196.69"
        $s36 = "192.241.215.118"
        $s37 = "198.61.227.6"
        $s38 = "198.74.56.124"
        $s39 = "198.199.69.31"
        $s40 = "198.199.75.69"
        $s41 = "198.199.79.133"
        $s42 = "198.199.79.201"
        $s43 = "198.199.79.222"
        $s44 = "198.199.79.239"
        $s45 = "198.199.105.51"
        $s46 = "198.199.110.187"
        $s47 = "212.71.250.4"
        $s48 = "87.106.24.200"
        $s49 = "87.106.26.9"
        $s50 = "46.4.80.102"
        $s51 = "54.227.61.124"
        $s52 = "198.58.124.24"
        $s53 = "198.177.254.186"
        $s54 = "50.62.12.103"
        $s55 = "166.78.62.91"
        $s56 = "166.78.144.80"
        $s57 = "23.21.71.54"
        $s58 = "54.209.178.183"
        $s59 = "81.166.122.234"
        $s60 = "95.211.120.23"
        $s61 = "95.211.172.143"
        $s62 = "173.193.197.194"
        $s63 = "87.255.51.229"
        $s64 = "192.42.116.41"
        $s65 = "192.42.119.41"
        $s66 = "50.22.145.246"
        $s67 = "50.23.174.203"
        $s68 = "54.83.43.69"
        $s69 = "82.165.25.167"
        $s70 = "82.165.25.209"
        $s71 = "82.165.25.210"
        $s72 = "212.227.20.19"
        $s73 = "50.116.32.177"
        $s74 = "50.116.56.144"
        $s75 = "66.175.212.197"
        $s76 = "69.164.203.105"
        $s77 = "72.14.182.233"
        $s78 = "109.74.196.143"
        $s79 = "173.230.133.99"
        $s80 = "178.79.190.156"
        $s81 = "198.74.50.135"
        $s82 = "91.233.244.102"
        $s83 = "91.233.244.106"
        $s84 = "148.81.111.111"
    condition:
        any of them
}

rule antisb_joesanbox {
     meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Joe Sandbox"
    version = "0.1"
    strings:
    $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
    $c1 = "RegQueryValue" 
    $s1 = "55274-640-2673064-23950" 
    condition:
        all of them
}

rule antisb_anubis {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Anubis"
    version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $c1 = "RegQueryValue" 
        $s1 = "76487-337-8429955-22614" 
        $s2 = "76487-640-1457236-23837" 
    condition:
        $p1 and $c1 and 1 of ($s*)
}

rule antisb_threatExpert {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for ThreatExpert"
    version = "0.1"
    strings:
        $f1 = "dbghelp.dll" nocase 
    condition:
        all of them
}

rule antisb_sandboxie {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Sandboxie"
    version = "0.1"
    strings:
        $f1 = "SbieDLL.dll" nocase 
    condition:
        all of them
}

rule antisb_cwsandbox {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for CWSandbox"
    version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $s1 = "76487-644-3177037-23510" 
    condition:
        all of them
}

rule antivm_virtualbox {
    meta:
        author = "x0r"
        description = "AntiVM checks for VirtualBox"
    version = "0.1"
    strings:
        $s1 = "VBoxService.exe" nocase
    condition:
        any of them
}

rule antivm_vmware {
    meta:
        author = "x0r"
        description = "AntiVM checks for VMWare"
    version = "0.1"
    strings:
        $s1 = "vmware.exe" nocase
        $s2 = "vmware-authd.exe" nocase
        $s3 = "vmware-hostd.exe" nocase
        $s4 = "vmware-tray.exe" nocase
        $s5 = "vmware-vmx.exe" nocase
        $s6 = "vmnetdhcp.exe" nocase
        $s7 = "vpxclient.exe" nocase
        $s8 = { b868584d56bb00000000b90a000000ba58560000ed }
    condition:
        any of them
}

rule antivm_bios {
    meta:
        author = "x0r"
        description = "AntiVM checks for Bios version"
    version = "0.2"
    strings:
        $p1 = "HARDWARE\\DESCRIPTION\\System" nocase
        $p2 = "HARDWARE\\DESCRIPTION\\System\\BIOS" nocase
        $c1 = "RegQueryValue" 
        $r1 = "SystemBiosVersion" 
        $r2 = "VideoBiosVersion" 
        $r3 = "SystemManufacturer" 
    condition:
        1 of ($p*) and 1 of ($c*) and 1 of ($r*)
}

rule disable_antivirus {
    meta:
        author = "x0r"
        description = "Disable AntiVirus"
    version = "0.2"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" nocase
        $p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
        $p3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase
        $c1 = "RegSetValue" 
        $r1 = "AntiVirusDisableNotify" 
        $r2 = "DontReportInfectionInformation" 
        $r3 = "DisableAntiSpyware" 
        $r4 = "RunInvalidSignatures" 
        $r5 = "AntiVirusOverride" 
        $r6 = "CheckExeSignatures" 
        $f1 = "blackd.exe" nocase
        $f2 = "blackice.exe" nocase
        $f3 = "lockdown.exe" nocase
        $f4 = "lockdown2000.exe" nocase
        $f5 = "taskkill.exe" nocase
        $f6 = "tskill.exe" nocase
        $f7 = "smc.exe" nocase
        $f8 = "sniffem.exe" nocase
        $f9 = "zapro.exe" nocase
        $f10 = "zlclient.exe" nocase
        $f11 = "zonealarm.exe" nocase
    condition:
        ($c1 and $p1 and 1 of ($f*)) or ($c1 and $p2) or 1 of ($r*) or $p3
}

rule disable_uax {
    meta:
        author = "x0r"
        description = "Disable User Access Control"
    version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}

rule disable_firewall {
    meta:
        author = "x0r"
        description = "Disable Firewall"
    version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
        $c1 = "RegSetValue" 
        $r1 = "FirewallPolicy" 
        $r2 = "EnableFirewall" 
        $r3 = "FirewallDisableNotify" 
        $s1 = "netsh firewall add allowedprogram"
    condition:
        (1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}

rule disable_registry {
    meta:
        author = "x0r"
        description = "Disable Registry editor"
    version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $c1 = "RegSetValue" 
        $r1 = "DisableRegistryTools" 
        $r2 = "DisableRegedit" 
    condition:
        1 of ($p*) and $c1 and 1 of ($r*)
}

rule disable_dep {
    meta:
        author = "x0r"
        description = "Bypass DEP"
    version = "0.1"
    strings:
        $c1 = "EnableExecuteProtectionSupport" 
        $c2 = "NtSetInformationProcess" 
        $c3 = "VirtualProctectEx" 
        $c4 = "SetProcessDEPPolicy" 
        $c5 = "ZwProtectVirtualMemory" 
    condition:
        any of them
}

rule disable_taskmanager {
    meta:
        author = "x0r"
        description = "Disable Task Manager"
    version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $r1 = "DisableTaskMgr" 
    condition:
        1 of ($p*) and 1 of ($r*)
}

rule inject_thread {
    meta:
        author = "x0r"
        description = "Code injection with CreateRemoteThread in a remote process"
    version = "0.1"
    strings:
        $c1 = "OpenProcess" 
        $c2 = "VirtualAllocEx" 
        $c3 = "NtWriteVirtualMemory" 
        $c4 = "WriteProcessMemory" 
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
        $c7 = "OpenProcess" 
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 or $c6 or $c7 )
}

rule create_process {
    meta:
        author = "x0r"
        description = "Create a new process"
    version = "0.2"
    strings:
        $f1 = "Shell32.dll" nocase
        $f2 = "Kernel32.dll" nocase
        $c1 = "ShellExecute" 
        $c2 = "WinExec" 
        $c3 = "CreateProcess"
        $c4 = "CreateThread"
    condition:
        ($f1 and $c1 ) or $f2 and ($c2 or $c3 or $c4)
}

rule persistence {
    meta:
        author = "x0r"
        description = "Install itself for autorun at Windows startup"
    version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $p2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $p3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" nocase
        $p4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" nocase
        $p5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $p6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" nocase
        $p7 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\" nocase
        $p8 = "SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\Windows" nocase
        $p9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler" nocase
        $p10 = "comfile\\shell\\open\\command" nocase
        $p11 = "piffile\\shell\\open\\command" nocase
        $p12 = "exefile\\shell\\open\\command" nocase
        $p13 = "txtfile\\shell\\open\\command" nocase
    $p14 = "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        $f1 = "win.ini" nocase
        $f2 = "system.ini" nocase
        $f3 = "Start Menu\\Programs\\Startup" nocase
    condition:
        any of them
}

rule hijack_network {
    meta:
        author = "x0r"
        description = "Hijack network configuration"
    version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Classes\\PROTOCOLS\\Handler" nocase
        $p2 = "SOFTWARE\\Classes\\PROTOCOLS\\Filter" nocase
        $p3 = "Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer" nocase
        $p4 = "software\\microsoft\\windows\\currentversion\\internet settings\\proxyenable" nocase
        $f1 = "drivers\\etc\\hosts" nocase
    condition:
        any of them
}

rule create_service {
    meta:
        author = "x0r"
        description = "Create a windows service"
    version = "0.2"
    strings:
    $f1 = "Advapi32.dll" nocase
        $c1 = "CreateService" 
        $c2 = "ControlService" 
        $c3 = "StartService" 
        $c4 = "QueryServiceStatus" 
    condition:
        all of them
}

rule create_com_service {
    meta:
        author = "x0r"
        description = "Create a COM server"
    version = "0.1"
    strings:
        $c1 = "DllCanUnloadNow" nocase
        $c2 = "DllGetClassObject" 
        $c3 = "DllInstall" 
        $c4 = "DllRegisterServer" 
        $c5 = "DllUnregisterServer" 
    condition:
        all of them
}

rule network_udp_sock {
    meta:
        author = "x0r"
        description = "Communications over UDP network"
    version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
    $f2 = "System.Net" nocase
        $f3 = "wsock32.dll" nocase
        $c0 = "WSAStartup" 
        $c1 = "sendto" 
        $c2 = "recvfrom" 
        $c3 = "WSASendTo" 
        $c4 = "WSARecvFrom" 
        $c5 = "UdpClient" 
    condition:
        (($f1 or $f3) and 2 of ($c*)) or ($f2 and $c5)
}

rule network_tcp_listen {
    meta:
        author = "x0r"
        description = "Listen for incoming communication"
    version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
        $f2 = "Mswsock.dll" nocase
        $f3 = "System.Net" nocase
        $f4 = "wsock32.dll" nocase
        $c1 = "bind" 
        $c2 = "accept" 
        $c3 = "GetAcceptExSockaddrs"
        $c4 = "AcceptEx" 
        $c5 = "WSAStartup" 
        $c6 = "WSAAccept" 
        $c7 = "WSASocket" 
        $c8 = "TcpListener" 
        $c9 = "AcceptTcpClient"
        $c10 = "listen"
    condition:
        1 of ($f*) and 2 of ($c*)
}

rule network_dyndns {
    meta:
        author = "x0r"
        description = "Communications dyndns network"
    version = "0.1"
    strings:    
    $s1 =".no-ip.org"
        $s2 =".publicvm.com"
        $s3 =".linkpc.net"
        $s4 =".dynu.com"
        $s5 =".dynu.net"
        $s6 =".afraid.org"
        $s7 =".chickenkiller.com"
        $s8 =".crabdance.com"
        $s9 =".ignorelist.com"
        $s10 =".jumpingcrab.com"
        $s11 =".moo.com"
        $s12 =".strangled.com"
        $s13 =".twillightparadox.com"
        $s14 =".us.to"
        $s15 =".strangled.net"
        $s16 =".info.tm"
        $s17 =".homenet.org"
        $s18 =".biz.tm"
        $s19 =".continent.kz"
        $s20 =".ax.lt"
        $s21 =".system-ns.com"
        $s22 =".adultdns.com"
        $s23 =".craftx.biz"
        $s24 =".ddns01.com"
        $s25 =".dns53.biz"
        $s26 =".dnsapi.info"
        $s27 =".dnsd.info"
        $s28 =".dnsdynamic.com"
        $s29 =".dnsdynamic.net"
        $s30 =".dnsget.org"
        $s31 =".fe100.net"
        $s32 =".flashserv.net"
        $s33 =".ftp21.net"
    condition:
        any of them
}

rule network_toredo {
    meta:
        author = "x0r"
        description = "Communications over Toredo network"
    version = "0.1"
    strings:    
    $f1 = "FirewallAPI.dll" nocase
        $p1 = "\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\" nocase
    condition:
        all of them
}

rule network_smtp_dotNet {
    meta:
        author = "x0r"
        description = "Communications smtp"
    version = "0.1"
    strings:    
    $f1 = "System.Net.Mail" nocase
        $p1 = "SmtpClient" nocase
    condition:
        all of them
}

rule network_smtp_raw {
    meta:
        author = "x0r"
        description = "Communications smtp"
    version = "0.1"
    strings:    
    $s1 = "MAIL FROM:" nocase
        $s2 = "RCPT TO:" nocase
    condition:
        all of them
}

rule network_smtp_vb {
    meta:
        author = "x0r"
        description = "Communications smtp"
    version = "0.1"
    strings:    
    $c1 = "CDO.Message" nocase
        $c2 = "cdoSMTPServer" nocase
        $c3 = "cdoSendUsingMethod" nocase
        $c4 = "cdoex.dll" nocase
        $c5 = "/cdo/configuration/smtpserver" nocase
    condition:
        any of them
}

rule network_p2p_win {
    meta:
        author = "x0r"
        description = "Communications over P2P network"
    version = "0.1"
    strings:    
        $c1 = "PeerCollabExportContact"
        $c2 = "PeerCollabGetApplicationRegistrationInfo"
        $c3 = "PeerCollabGetEndpointName"
        $c4 = "PeerCollabGetEventData"
        $c5 = "PeerCollabGetInvitationResponse"
        $c6 = "PeerCollabGetPresenceInfo"
        $c7 = "PeerCollabGetSigninOptions"
        $c8 = "PeerCollabInviteContact"
        $c9 = "PeerCollabInviteEndpoint"
        $c10 = "PeerCollabParseContact"
        $c11 = "PeerCollabQueryContactData"
        $c12 = "PeerCollabRefreshEndpointData"
        $c13 = "PeerCollabRegisterApplication"
        $c14 = "PeerCollabRegisterEvent"
        $c15 = "PeerCollabSetEndpointName"
        $c16 = "PeerCollabSetObject"
        $c17 = "PeerCollabSetPresenceInfo"
        $c18 = "PeerCollabSignout"
        $c19 = "PeerCollabUnregisterApplication"
        $c20 = "PeerCollabUpdateContact"
    condition:
        5 of them
}

rule network_tor {
    meta:
        author = "x0r"
        description = "Communications over TOR network"
    version = "0.1"
    strings:
        $p1 = "tor\\hidden_service\\private_key" nocase
        $p2 = "tor\\hidden_service\\hostname" nocase
        $p3 = "tor\\lock" nocase
        $p4 = "tor\\state" nocase
    condition:
        any of them
}
rule network_irc {
    meta:
        author = "x0r"
        description = "Communications over IRC network"
    version = "0.1"
    strings:
        $s1 = "NICK" 
        $s2 = "PING" 
        $s3 = "JOIN" 
        $s4 = "USER" 
        $s5 = "PRIVMSG" 
    condition:
        all of them
}

rule network_http {
    meta:
        author = "x0r"
        description = "Communications over HTTP"
    version = "0.1"
    strings:
        $f1 = "wininet.dll" nocase
        $c1 = "InternetConnect" 
        $c2 = "InternetOpen" 
        $c3 = "InternetOpenUrl" 
        $c4 = "InternetReadFile" 
        $c5 = "InternetWriteFile" 
        $c6 = "HttpOpenRequest" 
        $c7 = "HttpSendRequest" 
        $c8 = "IdHTTPHeaderInfo" 
    condition:
        $f1 and $c1 and ($c2 or $c3) and ($c4 or $c5 or $c6 or $c7 or $c8)
}

rule network_dropper {
    meta:
        author = "x0r"
        description = "File downloader/dropper" 
    version = "0.1"
    strings:
        $f1 = "urlmon.dll" nocase
        $c1 = "URLDownloadToFile" 
        $c2 = "URLDownloadToCacheFile" 
        $c3 = "URLOpenStream" 
        $c4 = "URLOpenPullStream" 
    condition:
        $f1 and 1 of ($c*)
}

rule network_ftp {
    meta:
        author = "x0r"
        description = "Communications over FTP" 
    version = "0.1"
    strings:
       $f1 = "Wininet.dll" nocase
        $c1 = "FtpGetCurrentDirectory" 
        $c2 = "FtpGetFile" 
        $c3 = "FtpPutFile" 
        $c4 = "FtpSetCurrentDirectory" 
        $c5 = "FtpOpenFile" 
        $c6 = "FtpGetFileSize" 
        $c7 = "FtpDeleteFile" 
        $c8 = "FtpCreateDirectory" 
        $c9 = "FtpRemoveDirectory" 
        $c10 = "FtpRenameFile" 
        $c11 = "FtpDownload" 
        $c12 = "FtpUpload" 
        $c13 = "FtpGetDirectory" 
    condition:
        $f1 and (4 of ($c*))
}

rule network_tcp_socket {
    meta:
        author = "x0r"
        description = "Communications over RAW socket"
    version = "0.1"
    strings:
    $f1 = "Ws2_32.dll" nocase
        $f2 = "wsock32.dll" nocase
        $c1 = "WSASocket" 
        $c2 = "socket" 
        $c3 = "send" 
        $c4 = "WSASend" 
        $c5 = "WSAConnect"
        $c6 = "connect"
        $c7 = "WSAStartup"
        $c8 = "closesocket"
        $c9 = "WSACleanup"
    condition:
        1 of ($f*) and 2 of ($c*)
}

rule network_dns {
    meta:
        author = "x0r"
        description = "Communications use DNS"
    version = "0.1"
    strings:
        $f1 = "System.Net" 
        $f2 = "Ws2_32.dll" nocase
        $f3 = "Dnsapi.dll" nocase
        $f4 = "wsock32.dll" nocase        
        $c2 = "GetHostEntry" 
        $c3 = "getaddrinfo"
        $c4 = "gethostbyname"
        $c5 = "WSAAsyncGetHostByName"
        $c6 = "DnsQuery"
    condition:
        1 of ($f*) and  1 of ($c*) 
}

rule network_ssl {
    meta:
        author = "x0r"
        description = "Communications over SSL"
        version = "0.1"
    strings:
        $f1 = "ssleay32.dll" nocase
        $f2 = "libeay32.dll" nocase
        $f3 = "libssl32.dll" nocase
        $c1 = "IdSSLOpenSSL" nocase
    condition:
        any of them
}

rule network_dga {
    meta:
        author = "x0r"
        description = "Communication using dga"
    version = "0.1"
    strings: 
        $dll1 = "Advapi32.dll" nocase
        $dll2 = "wininet.dll" nocase
        $dll3 = "Crypt32.dll" nocase
        $time1 = "SystemTimeToFileTime"  
        $time2 = "GetSystemTime"  
        $time3 = "GetSystemTimeAsFileTime"  
        $hash1 = "CryptCreateHash" 
        $hash2 = "CryptAcquireContext" 
        $hash3 = "CryptHashData" 
        $net1 = "InternetOpen"  
        $net2 = "InternetOpenUrl"  
        $net3 = "gethostbyname"  
        $net4 = "getaddrinfo"  
    condition:
        all of ($dll*) and 1 of ($time*) and 1 of ($hash*) and 1 of ($net*) 
}


rule bitcoin {
    meta:
        author = "x0r"
        description = "Perform crypto currency mining"
    version = "0.1"
    strings:
        $f1 = "OpenCL.dll" nocase
        $f2 = "nvcuda.dll" nocase
        $f3 = "opengl32.dll" nocase
        $s1 = "cpuminer 2.2.2X-Mining-Extensions"
        $s2 = "cpuminer 2.2.3X-Mining-Extensions"
        $s3 = "Ufasoft bitcoin-miner/0.20"
        $s4 = "bitcoin" nocase
        $s5 = "stratum" nocase
    condition:
        1 of ($f*) and 1 of ($s*)
}

rule certificate {
    meta:
        author = "x0r"
        description = "Inject certificate in store"
    version = "0.1"
    strings:
        $f1 = "Crypt32.dll" nocase
        $r1 = "software\\microsoft\\systemcertificates\\spc\\certificates" nocase
        $c1 = "CertOpenSystemStore" 
    condition:
    all of them
}

rule escalate_priv {
    meta:
        author = "x0r"
        description = "Escalade priviledges"
    version = "0.1"
    strings:
        $d1 = "Advapi32.dll" nocase
        $c1 = "SeDebugPrivilege" 
        $c2 = "AdjustTokenPrivileges" 
    condition:
        1 of ($d*) and 1 of ($c*)
}

rule screenshot {
    meta:
        author = "x0r"
        description = "Take screenshot"
    version = "0.1"
    strings:
        $d1 = "Gdi32.dll" nocase
        $d2 = "User32.dll" nocase
        $c1 = "BitBlt" 
        $c2 = "GetDC" 
    condition:
        1 of ($d*) and 1 of ($c*)
}

rule lookupip {
    meta:
        author = "x0r"
        description = "Lookup external IP"
    version = "0.1"
    strings:
        $n1 = "checkip.dyndns.org" nocase
        $n2 = "whatismyip.org" nocase
        $n3 = "whatsmyipaddress.com" nocase
        $n4 = "getmyip.org" nocase
        $n5 = "getmyip.co.uk" nocase
    condition:
        any of them
}

rule dyndns {
    meta:
        author = "x0r"
        description = "Dynamic DNS"
    version = "0.1"
    strings:
        $s1 = "SOFTWARE\\Vitalwerks\\DUC" nocase
    condition:
        any of them
}

rule lookupgeo {
    meta:
        author = "x0r"
        description = "Lookup Geolocation"
    version = "0.1"
    strings:
        $n1 = "j.maxmind.com" nocase
    condition:
        any of them
}

rule keylogger {
    meta:
        author = "x0r"
        description = "Run a keylogger"
    version = "0.1"
    strings:
        $f1 = "User32.dll" nocase
        $c1 = "GetAsyncKeyState" 
        $c2 = "GetKeyState" 
        $c3 = "MapVirtualKey" 
        $c4 = "GetKeyboardType"
    condition:
        $f1 and 1 of ($c*)
}

rule cred_local {
    meta:
        author = "x0r"
        description = "Steal credential"
    version = "0.1"
    strings:
        $c1 = "LsaEnumerateLogonSessions"
        $c2 = "SamIConnect"
        $c3 = "SamIGetPrivateData"
        $c4 = "SamQueryInformationUse"
        $c5 = "CredEnumerateA"
        $c6 = "CredEnumerateW"
        $r1 = "software\\microsoft\\internet account manager" nocase
        $r2 = "software\\microsoft\\identitycrl\\creds" nocase
        $r3 = "Security\\Policy\\Secrets"
    condition:
        any of them
}


rule sniff_audio {
    meta:
        author = "x0r"
        description = "Record Audio"
        version = "0.1"
    strings:
        $f1 = "winmm.dll" nocase
        $c1 = "waveInStart"
        $c2 = "waveInReset"
        $c3 = "waveInAddBuffer"
        $c4 = "waveInOpen"
        $c5 = "waveInClose"
    condition:
        $f1 and 2 of ($c*)
}

rule cred_ff {
    meta:
        author = "x0r"
        description = "Steal Firefox credential"
    version = "0.1"
    strings:
        $f1 = "signons.sqlite"
        $f2 = "signons3.txt"
        $f3 = "secmod.db"
        $f4 = "cert8.db"
        $f5 = "key3.db"
    condition:
        any of them
}

rule cred_vnc {
    meta:
        author = "x0r"
        description = "Steal VNC credential"
    version = "0.1"
    strings:
        $s1 = "VNCPassView"
    condition:
        all of them
}

rule cred_ie7 {
    meta:
        author = "x0r"
        description = "Steal IE 7 credential"
    version = "0.1"
    strings:
        $f1 = "Crypt32.dll" nocase
        $c1 = "CryptUnprotectData" 
        $s1 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" nocase
    condition:
        all of them
}

rule sniff_lan {
    meta:
        author = "x0r"
        description = "Sniff Lan network traffic"
    version = "0.1"
    strings:
        $f1 = "packet.dll" nocase
        $f2 = "npf.sys" nocase
        $f3 = "wpcap.dll" nocase
        $f4 = "winpcap.dll" nocase
    condition:
        any of them
}

rule migrate_apc {
    meta:
        author = "x0r"
        description = "APC queue tasks migration"
    version = "0.1"
    strings:
        $c1 = "OpenThread" 
        $c2 = "QueueUserAPC" 
    condition:
        all of them
}

rule spreading_file {
    meta:
        author = "x0r"
        description = "Malware can spread east-west file"
    version = "0.1"
    strings:
        $f1 = "autorun.inf" nocase
        $f2 = "desktop.ini" nocase
        $f3 = "desktop.lnk" nocase
    condition:
        any of them
}

rule spreading_share {
    meta:
        author = "x0r"
        description = "Malware can spread east-west using share drive"
        version = "0.1"
    strings:
        $f1 = "netapi32.dll" nocase
        $c1 = "NetShareGetInfo" 
        $c2 = "NetShareEnum" 
    condition:
        $f1 and 1 of ($c*)
}

rule rat_vnc {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit VNC"
    version = "0.1"
    strings:
        $f1 = "ultravnc.ini" nocase
        $c2 = "StartVNC" 
        $c3 = "StopVNC" 
    condition:
        any of them
}

rule rat_rdp {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable RDP"
    version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
        $p2 = "software\\microsoft\\windows nt\\currentversion\\terminal server" nocase
        $p3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" nocase
        $r1 = "EnableAdminTSRemote"
        $c1 = "net start termservice"
        $c2 = "sc config termservice start"
    condition:
        any of them
}

rule rat_telnet {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable Telnet"
        version = "0.1"
    strings:
        $r1 = "software\\microsoft\\telnetserver" nocase
    condition:
        any of them
}


rule rat_webcam {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit using webcam"
        version = "0.1"
    strings:
        $f1 = "avicap32.dll" nocase
        $c1 = "capCreateCaptureWindow" nocase
    condition:
        all of them
}

rule check_patchlevel {
    meta:
        author = "x0r"
        description = "Check if hotfix are applied"
    version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase
    condition:
        any of them
}

rule win_mutex {
    meta:
        author = "x0r"
        description = "Create or check mutex"
    version = "0.1"
    strings:
        $c1 = "CreateMutex" 
    condition:
        1 of ($c*)
}

rule win_registry {
    meta:
        author = "x0r"
        description = "Affect system registries"
    version = "0.1"
    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "RegQueryValueExA"
        $c2 = "RegOpenKeyExA"
        $c3 = "RegCloseKey"
        $c4 = "RegSetValueExA"
        $c5 = "RegCreateKeyA"
        $c6 = "RegCloseKey"                  
    condition:
        $f1 and 1 of ($c*)
}

rule win_token {
    meta:
        author = "x0r"
        description = "Affect system token"
    version = "0.1"
    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "DuplicateTokenEx"
        $c2 = "AdjustTokenPrivileges"
        $c3 = "OpenProcessToken"
        $c4 = "LookupPrivilegeValueA"            
    condition:
        $f1 and 1 of ($c*)
}

rule win_private_profile {
    meta:
        author = "x0r"
        description = "Affect private profile"
    version = "0.1"
    strings:
        $f1 = "kernel32.dll" nocase
        $c1 = "GetPrivateProfileIntA"
        $c2 = "GetPrivateProfileStringA"
        $c3 = "WritePrivateProfileStringA"         
    condition:
        $f1 and 1 of ($c*)
}

rule win_files_operation {
    meta:
        author = "x0r"
        description = "Affect private profile"
    version = "0.1"
    strings:
        $f1 = "kernel32.dll" nocase
        $c1 = "WriteFile"
        $c2 = "SetFilePointer"
        $c3 = "WriteFile"
        $c4 = "ReadFile"
        $c5 = "DeleteFileA"
        $c6 = "CreateFileA"
        $c7 = "FindFirstFileA"
        $c8 = "MoveFileExA"
        $c9 = "FindClose"
        $c10 = "SetFileAttributesA"
        $c11 = "CopyFile"

    condition:
        $f1 and 3 of ($c*)
}


rule win_hook {
    meta:
        author = "x0r"
        description = "Affect hook table"
    version = "0.1"
    strings:
        $f1 = "user32.dll" nocase
        $c1 = "UnhookWindowsHookEx"
        $c2 = "SetWindowsHookExA"
        $c3 = "CallNextHookEx"         
    condition:
        $f1 and 1 of ($c*)
}