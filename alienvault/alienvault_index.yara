
rule LIGHTDART_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "ret.log" wide ascii
                $s2 = "Microsoft Internet Explorer 6.0" wide ascii
                $s3 = "szURL Fail" wide ascii
                $s4 = "szURL Successfully" wide ascii
                $s5 = "%s&sdate=%04ld-%02ld-%02ld" wide ascii
        condition:
                all of them
}

rule AURIGA_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "superhard corp." wide ascii
                $s2 = "microsoft corp." wide ascii
                $s3 = "[Insert]" wide ascii
                $s4 = "[Delete]" wide ascii
                $s5 = "[End]" wide ascii
                $s6 = "!(*@)(!@KEY" wide ascii
                $s7 = "!(*@)(!@SID=" wide ascii
        condition:
                all of them
}

rule AURIGA_driver_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Services\\riodrv32" wide ascii
                $s2 = "riodrv32.sys" wide ascii
                $s3 = "svchost.exe" wide ascii
                $s4 = "wuauserv.dll" wide ascii
                $s5 = "arp.exe" wide ascii
                $pdb = "projects\\auriga" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule BANGAT_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "superhard corp." wide ascii
                $s2 = "microsoft corp." wide ascii
                $s3 = "[Insert]" wide ascii
                $s4 = "[Delete]" wide ascii
                $s5 = "[End]" wide ascii
                $s6 = "!(*@)(!@KEY" wide ascii
                $s7 = "!(*@)(!@SID=" wide ascii
                $s8 = "end      binary output" wide ascii
                $s9 = "XriteProcessMemory" wide ascii
                $s10 = "IE:Password-Protected sites" wide ascii
                $s11 = "pstorec.dll" wide ascii

        condition:
                all of them
}

rule BISCUIT_GREENCAT_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "zxdosml" wide ascii
                $s2 = "get user name error!" wide ascii
                $s3 = "get computer name error!" wide ascii
                $s4 = "----client system info----" wide ascii
                $s5 = "stfile" wide ascii
                $s6 = "cmd success!" wide ascii

        condition:
                all of them
}

rule BOUNCER_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg" wide ascii
                $s2 = "IDR_DATA%d" wide ascii

                $s3 = "asdfqwe123cxz" wide ascii
                $s4 = "Mode must be 0(encrypt) or 1(decrypt)." wide ascii

        condition:
                ($s1 and $s2) or ($s3 and $s4)

}

rule BOUNCER_DLL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "new_connection_to_bounce():" wide ascii
                $s2 = "usage:%s IP port [proxip] [port] [key]" wide ascii

        condition:
                all of them
}

rule CALENDAR_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "content" wide ascii
                $s2 = "title" wide ascii
                $s3 = "entry" wide ascii
                $s4 = "feed" wide ascii
                $s5 = "DownRun success" wide ascii
                $s6 = "%s@gmail.com" wide ascii
                $s7 = "<!--%s-->" wide ascii

                $b8 = "W4qKihsb+So=" wide ascii
                $b9 = "PoqKigY7ggH+VcnqnTcmhFCo9w==" wide ascii
                $b10 = "8oqKiqb5880/uJLzAsY=" wide ascii

        condition:
                all of ($s*) or all of ($b*)
}

rule COMBOS_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla4.0 (compatible; MSIE 7.0; Win32)" wide ascii
                $s2 = "Mozilla5.1 (compatible; MSIE 8.0; Win32)" wide ascii
                $s3 = "Delay" wide ascii
                $s4 = "Getfile" wide ascii
                $s5 = "Putfile" wide ascii
                $s6 = "---[ Virtual Shell]---" wide ascii
                $s7 = "Not Comming From Our Server %s." wide ascii


        condition:
                all of them
}

rule DAIRY_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; MSIE 7.0;)" wide ascii
                $s2 = "KilFail" wide ascii
                $s3 = "KilSucc" wide ascii
                $s4 = "pkkill" wide ascii
                $s5 = "pklist" wide ascii


        condition:
                all of them
}

rule GLOOXMAIL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Kill process success!" wide ascii
                $s2 = "Kill process failed!" wide ascii
                $s3 = "Sleep success!" wide ascii
                $s4 = "based on gloox" wide ascii

                $pdb = "glooxtest.pdb" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule GOGGLES_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Kill process success!" wide ascii
                $s2 = "Kill process failed!" wide ascii
                $s3 = "Sleep success!" wide ascii
                $s4 = "based on gloox" wide ascii

                $pdb = "glooxtest.pdb" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule HACKSFASE1_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = {cb 39 82 49 42 be 1f 3a}

        condition:
                all of them
}

rule HACKSFASE2_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Send to Server failed." wide ascii
                $s2 = "HandShake with the server failed. Error:" wide ascii
                $s3 = "Decryption Failed. Context Expired." wide ascii

        condition:
                all of them
}

rule KURTON_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; MSIE8.0; Windows NT 5.1)" wide ascii
                $s2 = "!(*@)(!@PORT!(*@)(!@URL" wide ascii
                $s3 = "MyTmpFile.Dat" wide ascii
                $s4 = "SvcHost.DLL.log" wide ascii

        condition:
                all of them
}

rule LONGRUN_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0)" wide ascii
                $s2 = "%s\\%c%c%c%c%c%c%c" wide ascii
                $s3 = "wait:" wide ascii
                $s4 = "Dcryption Error! Invalid Character" wide ascii

        condition:
                all of them
}

rule MACROMAIL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "svcMsn.dll" wide ascii
                $s2 = "RundllInstall" wide ascii
                $s3 = "Config service %s ok." wide ascii
                $s4 = "svchost.exe" wide ascii

        condition:
                all of them
}

rule MANITSME_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Install an Service hosted by SVCHOST." wide ascii
                $s2 = "The Dll file that to be released." wide ascii
                $s3 = "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
                $s4 = "svchost.exe" wide ascii

                $e1 = "Man,it's me" wide ascii
                $e2 = "Oh,shit" wide ascii
                $e3 = "Hallelujah" wide ascii
                $e4 = "nRet == SOCKET_ERROR" wide ascii

                $pdb1 = "rouji\\release\\Install.pdb" wide ascii
                $pdb2 = "rouji\\SvcMain.pdb" wide ascii

        condition:
                (all of ($s*)) or (all of ($e*)) or $pdb1 or $pdb2
}

rule MINIASP_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "miniasp" wide ascii
                $s2 = "wakeup=" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "command is null!" wide ascii
                $s5 = "device_input.asp?device_t=" wide ascii


        condition:
                all of them
}

rule NEWSREELS_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0)" wide ascii
                $s2 = "name=%s&userid=%04d&other=%c%s" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "command is null!" wide ascii
                $s5 = "noclient" wide ascii
                $s6 = "wait" wide ascii
                $s7 = "active" wide ascii
                $s8 = "hello" wide ascii


        condition:
                all of them
}

rule SEASALT_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.00; Windows 98) KSMM" wide ascii
                $s2 = "upfileok" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "upfileer" wide ascii
                $s5 = "fxftest" wide ascii


        condition:
                all of them
}

rule STARSYPOUND_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "*(SY)# cmd" wide ascii
                $s2 = "send = %d" wide ascii
                $s3 = "cmd.exe" wide ascii
                $s4 = "*(SY)#" wide ascii


        condition:
                all of them
}

rule SWORD_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "@***@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@>>>" wide ascii
                $s2 = "sleep:" wide ascii
                $s3 = "down:" wide ascii
                $s4 = "*========== Bye Bye ! ==========*" wide ascii


        condition:
                all of them
}


rule thequickbrow_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "thequickbrownfxjmpsvalzydg" wide ascii


        condition:
                all of them
}


rule TABMSGSQL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "letusgohtppmmv2.0.0.1" wide ascii
                $s2 = "Mozilla/4.0 (compatible; )" wide ascii
                $s3 = "filestoc" wide ascii
                $s4 = "filectos" wide ascii
                $s5 = "reshell" wide ascii

        condition:
                all of them
}

rule CCREWBACK1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "postvalue" wide ascii
    $b = "postdata" wide ascii
    $c = "postfile" wide ascii
    $d = "hostname" wide ascii
    $e = "clientkey" wide ascii
    $f = "start Cmd Failure!" wide ascii
    $g = "sleep:" wide ascii
    $h = "downloadcopy:" wide ascii
    $i = "download:" wide ascii
    $j = "geturl:" wide ascii
    $k = "1.234.1.68" wide ascii

  condition:
    4 of ($a,$b,$c,$d,$e) or $f or 3 of ($g,$h,$i,$j) or $k
}

rule TrojanCookies_CCREW
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "sleep:" wide ascii
    $b = "content=" wide ascii
    $c = "reqpath=" wide ascii
    $d = "savepath=" wide ascii
    $e = "command=" wide ascii


  condition:
    4 of ($a,$b,$c,$d,$e)
}

rule GEN_CCREW1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "W!r@o#n$g" wide ascii
    $b = "KerNel32.dll" wide ascii

  condition:
    any of them
}

rule Elise
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "SetElise.pdb" wide ascii

  condition:
    $a
}

rule EclipseSunCloudRAT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "Eclipse_A" wide ascii
    $b = "\\PJTS\\" wide ascii
    $c = "Eclipse_Client_B.pdb" wide ascii
    $d = "XiaoME" wide ascii
    $e = "SunCloud-Code" wide ascii
    $f = "/uc_server/data/forum.asp" wide ascii

  condition:
    any of them
}

rule MoonProject
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "Serverfile is smaller than Clientfile" wide ascii
    $b = "\\M tools\\" wide ascii
    $c = "MoonDLL" wide ascii
        $d = "\\M tools\\" wide ascii

  condition:
    any of them
}

rule ccrewDownloader1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = {DD B5 61 F0 20 47 20 57 D6 65 9C CB 31 1B 65 42}

  condition:
    any of them
}

rule ccrewDownloader2
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "3gZFQOBtY3sifNOl" wide ascii
        $b = "docbWUWsc2gRMv9HN7TFnvnKcrWUUFdAEem9DkqRALoD" wide ascii
        $c = "6QVSOZHQPCMc2A8HXdsfuNZcmUnIqWrOIjrjwOeagILnnScxadKEr1H2MZNwSnaJ" wide ascii

  condition:
    any of them
}


rule ccrewMiniasp
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "MiniAsp.pdb" wide ascii
    $b = "device_t=" wide ascii

  condition:
    any of them
}


rule ccrewSSLBack2
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = {39 82 49 42 BE 1F 3A}

  condition:
    any of them
}

rule ccrewSSLBack3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "SLYHKAAY" wide ascii

  condition:
    any of them
}


rule ccrewSSLBack1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "!@#%$^#@!" wide ascii
    $b = "64.91.80.6" wide ascii

  condition:
    any of them
}

rule ccrewDownloader3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "ejlcmbv" wide ascii
        $b = "bhxjuisv" wide ascii
        $c = "yqzgrh" wide ascii
        $d = "uqusofrp" wide ascii
        $e = "Ljpltmivvdcbb" wide ascii
        $f = "frfogjviirr" wide ascii
        $g = "ximhttoskop" wide ascii
  condition:
    4 of them
}


rule ccrewQAZ
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "!QAZ@WSX" wide ascii

  condition:
    $a
}

rule metaxcd
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "<meta xcd=" wide ascii

  condition:
    $a
}

rule MiniASP
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

strings:
    $KEY = { 71 30 6E 63 39 77 38 65 64 61 6F 69 75 6B 32 6D 7A 72 66 79 33 78 74 31 70 35 6C 73 36 37 67 34 62 76 68 6A }
    $PDB = "MiniAsp.pdb" nocase wide ascii

condition:
    any of them
}

rule DownloaderPossibleCCrew
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "%s?%.6u" wide ascii
    $b = "szFileUrl=%s" wide ascii
    $c = "status=%u" wide ascii
    $d = "down file success" wide ascii
        $e = "Mozilla/4.0 (compatible; MSIE 6.0; Win32)" wide ascii

  condition:
    all of them
}

rule APT1_MAPIGET
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $s1 = "%s\\Attachment.dat" wide ascii
        $s2 = "MyOutlook" wide ascii
        $s3 = "mail.txt" wide ascii
        $s4 = "Recv Time:" wide ascii
        $s5 = "Subject:" wide ascii

    condition:
        all of them
}

rule APT1_LIGHTBOLT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "bits.exe" wide ascii
        $str2 = "PDFBROW" wide ascii
        $str3 = "Browser.exe" wide ascii
        $str4 = "Protect!" wide ascii
    condition:
        2 of them
}

rule APT1_GETMAIL
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $stra1 = "pls give the FULL path" wide ascii
        $stra2 = "mapi32.dll" wide ascii
        $stra3 = "doCompress" wide ascii

        $strb1 = "getmail.dll" wide ascii
        $strb2 = "doCompress" wide ascii
        $strb3 = "love" wide ascii
    condition:
        all of ($stra*) or all of ($strb*)
}

rule APT1_GDOCUPLOAD
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "name=\"GALX\"" wide ascii
        $str2 = "User-Agent: Shockwave Flash" wide ascii
        $str3 = "add cookie failed..." wide ascii
        $str4 = ",speed=%f" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_Y21K
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "Y29ubmVjdA" wide ascii // connect
        $2 = "c2xlZXA" wide ascii // sleep
        $3 = "cXVpdA" wide ascii // quit
        $4 = "Y21k" wide ascii // cmd
        $5 = "dW5zdXBwb3J0" wide ascii // unsupport
    condition:
        4 of them
}

rule APT1_WEBC2_YAHOO
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $http1 = "HTTP/1.0" wide ascii
        $http2 = "Content-Type:" wide ascii
        $uagent = "IPHONE8.5(host:%s,ip:%s)" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_UGX
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $persis = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" wide ascii
        $exe = "DefWatch.exe" wide ascii
        $html = "index1.html" wide ascii
        $cmd1 = "!@#tiuq#@!" wide ascii
        $cmd2 = "!@#dmc#@!" wide ascii
        $cmd3 = "!@#troppusnu#@!" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_TOCK
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "InprocServer32" wide ascii
        $2 = "HKEY_PERFORMANCE_DATA" wide ascii
        $3 = "<!---[<if IE 5>]id=" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_TABLE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $msg1 = "Fail To Execute The Command" wide ascii
        $msg2 = "Execute The Command Successfully" wide ascii
        $gif1 = /\w+\.gif/
        $gif2 = "GIF89" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_RAVE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "iniet.exe" wide ascii
        $2 = "cmd.exe" wide ascii
        $3 = "SYSTEM\\CurrentControlSet\\Services\\DEVFS" wide ascii
        $4 = "Device File System" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_QBP
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "2010QBP" wide ascii
        $2 = "adobe_sl.exe" wide ascii
        $3 = "URLDownloadToCacheFile" wide ascii
        $4 = "dnsapi.dll" wide ascii
        $5 = "urlmon.dll" wide ascii
    condition:
        4 of them
}

rule APT1_WEBC2_KT3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "*!Kt3+v|" wide ascii
        //$2 = " s:" wide ascii
        //$3 = " dne" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_HEAD
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "Ready!" wide ascii
        $2 = "connect ok" wide ascii
        $3 = "WinHTTP 1.0" wide ascii
        $4 = "<head>" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_GREENCAT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "reader_sl.exe" wide ascii
        $2 = "MS80547.bat" wide ascii
        $3 = "ADR32" wide ascii
        $4 = "ControlService failed!" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_DIV
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "3DC76854-C328-43D7-9E07-24BF894F8EF5" wide ascii
        $2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $3 = "Hello from MFC!" wide ascii
        $4 = "Microsoft Internet Explorer" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_CSON
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $httpa1 = "/Default.aspx?INDEX=" wide ascii
        $httpa2 = "/Default.aspx?ID=" wide ascii
        $httpb1 = "Win32" wide ascii
        $httpb2 = "Accept: text*/*" wide ascii
        $exe1 = "xcmd.exe" wide ascii
        $exe2 = "Google.exe" wide ascii
    condition:
        1 of ($exe*) and 1 of ($httpa*) and all of ($httpb*)
}

rule APT1_WEBC2_CLOVER
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $msg1 = "BUILD ERROR!" wide ascii
        $msg2 = "SUCCESS!" wide ascii
        $msg3 = "wild scan" wide ascii
        $msg4 = "Code too clever" wide ascii
        $msg5 = "insufficient lookahead" wide ascii
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; SV1)" wide ascii
        $ua2 = "Mozilla/5.0 (Windows; Windows NT 5.1; en-US; rv:1.8.0.12) Firefox/1.5.0.12" wide ascii
    condition:
        2 of ($msg*) and 1 of ($ua*)
}

rule APT1_WEBC2_BOLID
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $vm = "VMProtect" wide ascii
        $http = "http://[c2_location]/[page].html" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_ADSPACE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "<!---HEADER ADSPACE style=" wide ascii
        $2 = "ERSVC.DLL" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_AUSOV
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "ntshrui.dll" wide ascii
        $2 = "%SystemRoot%\\System32\\" wide ascii
        $3 = "<!--DOCHTML" wide ascii
        $4 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" wide ascii
        $5 = "Ausov" wide ascii
    condition:
        4 of them
}

rule APT1_WARP
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $err1 = "exception..." wide ascii
        $err2 = "failed..." wide ascii
        $err3 = "opened..." wide ascii
        $exe1 = "cmd.exe" wide ascii
        $exe2 = "ISUN32.EXE" wide ascii
    condition:
        2 of ($err*) and all of ($exe*)
}

rule APT1_TARSIP_ECLIPSE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "\\pipe\\ssnp" wide ascii
        $2 = "toobu.ini" wide ascii
        $3 = "Serverfile is not bigger than Clientfile" wide ascii
        $4 = "URL download success" wide ascii
    condition:
        3 of them
}

rule APT1_TARSIP_MOON
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $s1 = "\\XiaoME\\SunCloud-Code\\moon" wide ascii
        $s2 = "URL download success!" wide ascii
        $s3 = "Kugoosoft" wide ascii
        $msg1 = "Modify file failed!! So strange!" wide ascii
        $msg2 = "Create cmd process failed!" wide ascii
        $msg3 = "The command has not been implemented!" wide ascii
        $msg4 = "Runas success!" wide ascii
        $onec1 = "onec.php" wide ascii
        $onec2 = "/bin/onec" wide ascii
    condition:
        1 of ($s*) and 1 of ($msg*) and 1 of ($onec*)
}

private rule APT1_payloads
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $pay1 = "rusinfo.exe" wide ascii
        $pay2 = "cmd.exe" wide ascii
        $pay3 = "AdobeUpdater.exe" wide ascii
        $pay4 = "buildout.exe" wide ascii
        $pay5 = "DefWatch.exe" wide ascii
        $pay6 = "d.exe" wide ascii
        $pay7 = "em.exe" wide ascii
        $pay8 = "IMSCMig.exe" wide ascii
        $pay9 = "localfile.exe" wide ascii
        $pay10 = "md.exe" wide ascii
        $pay11 = "mdm.exe" wide ascii
        $pay12 = "mimikatz.exe" wide ascii
        $pay13 = "msdev.exe" wide ascii
        $pay14 = "ntoskrnl.exe" wide ascii
        $pay15 = "p.exe" wide ascii
        $pay16 = "otepad.exe" wide ascii
        $pay17 = "reg.exe" wide ascii
        $pay18 = "regsvr.exe" wide ascii
        $pay19 = "runinfo.exe" wide ascii
        $pay20 = "AdobeUpdate.exe" wide ascii
        $pay21 = "inetinfo.exe" wide ascii
        $pay22 = "svehost.exe" wide ascii
        $pay23 = "update.exe" wide ascii
        $pay24 = "NTLMHash.exe" wide ascii
        $pay25 = "wpnpinst.exe" wide ascii
        $pay26 = "WSDbg.exe" wide ascii
        $pay27 = "xcmd.exe" wide ascii
        $pay28 = "adobeup.exe" wide ascii
        $pay29 = "0830.bin" wide ascii
        $pay30 = "1001.bin" wide ascii
        $pay31 = "a.bin" wide ascii
        $pay32 = "ISUN32.EXE" wide ascii
        $pay33 = "AcroRD32.EXE" wide ascii
        $pay34 = "INETINFO.EXE" wide ascii
    condition:
        1 of them
}

private rule APT1_RARSilent_EXE_PDF
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $winrar1 = "WINRAR.SFX" wide ascii
        $winrar2 = ";The comment below contains SFX script commands" wide ascii
        $winrar3 = "Silent=1" wide ascii

        $str1 = /Setup=[\s\w\"]+\.(exe|pdf|doc)/
        $str2 = "Steup=\"" wide ascii
    condition:
        all of ($winrar*) and 1 of ($str*)
}

rule APT1_aspnetreport
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $url = "aspnet_client/report.asp" wide ascii
        $param = "name=%s&Gender=%c&Random=%04d&SessionKey=%s" wide ascii
    condition:
        $url and $param and APT1_payloads
}

rule APT1_Revird_svc
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $dll1 = "nwwwks.dll" wide ascii
        $dll2 = "rdisk.dll" wide ascii
        $dll3 = "skeys.dll" wide ascii
        $dll4 = "SvcHost.DLL.log" wide ascii
        $svc1 = "InstallService" wide ascii
        $svc2 = "RundllInstallA" wide ascii
        $svc3 = "RundllUninstallA" wide ascii
        $svc4 = "ServiceMain" wide ascii
        $svc5 = "UninstallService" wide ascii
    condition:
        1 of ($dll*) and 2 of ($svc*)
}

rule APT1_letusgo
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $letus = /letusgo[\w]+v\d\d?\./
    condition:
        $letus
}

rule APT1_dbg_mess
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $dbg1 = "Down file ok!" wide ascii
        $dbg2 = "Send file ok!" wide ascii
        $dbg3 = "Command Error!" wide ascii
        $dbg4 = "Pls choose target first!" wide ascii
        $dbg5 = "Alert!" wide ascii
        $dbg6 = "Pls press enter to make sure!" wide ascii
        $dbg7 = "Are you sure to " wide ascii
    condition:
        4 of them and APT1_payloads
}

rule APT1_known_malicious_RARSilent
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "Analysis And Outlook.doc\"" wide ascii
        $str2 = "North Korean launch.pdf\"" wide ascii
        $str3 = "Dollar General.doc\"" wide ascii
        $str4 = "Dow Corning Corp.pdf\"" wide ascii
    condition:
        1 of them and APT1_RARSilent_EXE_PDF
}

rule avdetect_procs : avdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Antivirus detection tricks"

	strings:
		$proc2 = "LMon.exe" ascii wide
		$proc3 = "sagui.exe" ascii wide
		$proc4 = "RDTask.exe" ascii wide
		$proc5 = "kpf4gui.exe" ascii wide
		$proc6 = "ALsvc.exe" ascii wide
		$proc7 = "pxagent.exe" ascii wide
		$proc8 = "fsma32.exe" ascii wide
		$proc9 = "licwiz.exe" ascii wide
		$proc10 = "SavService.exe" ascii wide
		$proc11 = "prevxcsi.exe" ascii wide
		$proc12 = "alertwall.exe" ascii wide
		$proc13 = "livehelp.exe" ascii wide
		$proc14 = "SAVAdminService.exe" ascii wide
		$proc15 = "csi-eui.exe" ascii wide
		$proc16 = "mpf.exe" ascii wide
		$proc17 = "lookout.exe" ascii wide
		$proc18 = "savprogress.exe" ascii wide
		$proc19 = "lpfw.exe" ascii wide
		$proc20 = "mpfcm.exe" ascii wide
		$proc21 = "emlproui.exe" ascii wide
		$proc22 = "savmain.exe" ascii wide
		$proc23 = "outpost.exe" ascii wide
		$proc24 = "fameh32.exe" ascii wide
		$proc25 = "emlproxy.exe" ascii wide
		$proc26 = "savcleanup.exe" ascii wide
		$proc27 = "filemon.exe" ascii wide
		$proc28 = "AntiHook.exe" ascii wide
		$proc29 = "endtaskpro.exe" ascii wide
		$proc30 = "savcli.exe" ascii wide
		$proc31 = "procmon.exe" ascii wide
		$proc32 = "xfilter.exe" ascii wide
		$proc33 = "netguardlite.exe" ascii wide
		$proc34 = "backgroundscanclient.exe" ascii wide
		$proc35 = "Sniffer.exe" ascii wide
		$proc36 = "scfservice.exe" ascii wide
		$proc37 = "oasclnt.exe" ascii wide
		$proc38 = "sdcservice.exe" ascii wide
		$proc39 = "acs.exe" ascii wide
		$proc40 = "scfmanager.exe" ascii wide
		$proc41 = "omnitray.exe" ascii wide
		$proc42 = "sdcdevconx.exe" ascii wide
		$proc43 = "aupdrun.exe" ascii wide
		$proc44 = "spywaretermin" ascii wide
		$proc45 = "atorshield.exe" ascii wide
		$proc46 = "onlinent.exe" ascii wide
		$proc47 = "sdcdevconIA.exe" ascii wide
		$proc48 = "sppfw.exe" ascii wide
		$proc49 = "spywat~1.exe" ascii wide
		$proc50 = "opf.exe" ascii wide
		$proc51 = "sdcdevcon.exe" ascii wide
		$proc52 = "spfirewallsvc.exe" ascii wide
		$proc53 = "ssupdate.exe" ascii wide
		$proc54 = "pctavsvc.exe" ascii wide
		$proc55 = "configuresav.exe" ascii wide
		$proc56 = "fwsrv.exe" ascii wide
		$proc57 = "terminet.exe" ascii wide
		$proc58 = "pctav.exe" ascii wide
		$proc59 = "alupdate.exe" ascii wide
		$proc60 = "opfsvc.exe" ascii wide
		$proc61 = "tscutynt.exe" ascii wide
		$proc62 = "pcviper.exe" ascii wide
		$proc63 = "InstLsp.exe" ascii wide
		$proc64 = "uwcdsvr.exe" ascii wide
		$proc65 = "umxtray.exe" ascii wide
		$proc66 = "persfw.exe" ascii wide
		$proc67 = "CMain.exe" ascii wide
		$proc68 = "dfw.exe" ascii wide
		$proc69 = "updclient.exe" ascii wide
		$proc70 = "pgaccount.exe" ascii wide
		$proc71 = "CavAUD.exe" ascii wide
		$proc72 = "ipatrol.exe" ascii wide
		$proc73 = "webwall.exe" ascii wide
		$proc74 = "privatefirewall3.exe" ascii wide
		$proc75 = "CavEmSrv.exe" ascii wide
		$proc76 = "pcipprev.exe" ascii wide
		$proc77 = "winroute.exe" ascii wide
		$proc78 = "protect.exe" ascii wide
		$proc79 = "Cavmr.exe" ascii wide
		$proc80 = "prifw.exe" ascii wide
		$proc81 = "apvxdwin.exe" ascii wide
		$proc82 = "rtt_crc_service.exe" ascii wide
		$proc83 = "Cavvl.exe" ascii wide
		$proc84 = "tzpfw.exe" ascii wide
		$proc85 = "as3pf.exe" ascii wide
		$proc86 = "schedulerdaemon.exe" ascii wide
		$proc87 = "CavApp.exe" ascii wide
		$proc88 = "privatefirewall3.exe" ascii wide
		$proc89 = "avas.exe" ascii wide
		$proc90 = "sdtrayapp.exe" ascii wide
		$proc91 = "CavCons.exe" ascii wide
		$proc92 = "pfft.exe" ascii wide
		$proc93 = "avcom.exe" ascii wide
		$proc94 = "siteadv.exe" ascii wide
		$proc95 = "CavMud.exe" ascii wide
		$proc96 = "armorwall.exe" ascii wide
		$proc97 = "avkproxy.exe" ascii wide
		$proc98 = "sndsrvc.exe" ascii wide
		$proc99 = "CavUMAS.exe" ascii wide
		$proc100 = "app_firewall.exe" ascii wide
		$proc101 = "avkservice.exe" ascii wide
		$proc102 = "snsmcon.exe" ascii wide
		$proc103 = "UUpd.exe" ascii wide
		$proc104 = "blackd.exe" ascii wide
		$proc105 = "avktray.exe" ascii wide
		$proc106 = "snsupd.exe" ascii wide
		$proc107 = "cavasm.exe" ascii wide
		$proc108 = "blackice.exe" ascii wide
		$proc109 = "avkwctrl.exe" ascii wide
		$proc110 = "procguard.exe" ascii wide
		$proc111 = "CavSub.exe" ascii wide
		$proc112 = "umxagent.exe" ascii wide
		$proc113 = "avmgma.exe" ascii wide
		$proc114 = "DCSUserProt.exe" ascii wide
		$proc115 = "CavUserUpd.exe" ascii wide
		$proc116 = "kpf4ss.exe" ascii wide
		$proc117 = "avtask.exe" ascii wide
		$proc118 = "avkwctl.exe" ascii wide
		$proc119 = "CavQ.exe" ascii wide
		$proc120 = "tppfdmn.exe" ascii wide
		$proc121 = "aws.exe" ascii wide
		$proc122 = "firewall.exe" ascii wide
		$proc123 = "Cavoar.exe" ascii wide
		$proc124 = "blinksvc.exe" ascii wide
		$proc125 = "bgctl.exe" ascii wide
		$proc126 = "THGuard.exe" ascii wide
		$proc127 = "CEmRep.exe" ascii wide
		$proc128 = "sp_rsser.exe" ascii wide
		$proc129 = "bgnt.exe" ascii wide
		$proc130 = "spybotsd.exe" ascii wide
		$proc131 = "OnAccessInstaller.exe" ascii wide
		$proc132 = "op_mon.exe" ascii wide
		$proc133 = "bootsafe.exe" ascii wide
		$proc134 = "xauth_service.exe" ascii wide
		$proc135 = "SoftAct.exe" ascii wide
		$proc136 = "cmdagent.exe" ascii wide
		$proc137 = "bullguard.exe" ascii wide
		$proc138 = "xfilter.exe" ascii wide
		$proc139 = "CavSn.exe" ascii wide
		$proc140 = "VCATCH.EXE" ascii wide
		$proc141 = "cdas2.exe" ascii wide
		$proc142 = "zlh.exe" ascii wide
		$proc143 = "Packetizer.exe" ascii wide
		$proc144 = "SpyHunter3.exe" ascii wide
		$proc145 = "cmgrdian.exe" ascii wide
		$proc146 = "adoronsfirewall.exe" ascii wide
		$proc147 = "Packetyzer.exe" ascii wide
		$proc148 = "wwasher.exe" ascii wide
		$proc149 = "configmgr.exe" ascii wide
		$proc150 = "scfservice.exe" ascii wide
		$proc151 = "zanda.exe" ascii wide
		$proc152 = "authfw.exe" ascii wide
		$proc153 = "cpd.exe" ascii wide
		$proc154 = "scfmanager.exe" ascii wide
		$proc155 = "zerospywarele.exe" ascii wide
		$proc156 = "dvpapi.exe" ascii wide
		$proc157 = "espwatch.exe" ascii wide
		$proc158 = "dltray.exe" ascii wide
		$proc159 = "zerospywarelite_installer.exe" ascii wide
		$proc160 = "clamd.exe" ascii wide
		$proc161 = "fgui.exe" ascii wide
		$proc162 = "dlservice.exe" ascii wide
		$proc163 = "Wireshark.exe" ascii wide
		$proc164 = "sab_wab.exe" ascii wide
		$proc165 = "filedeleter.exe" ascii wide
		$proc166 = "ashwebsv.exe" ascii wide
		$proc167 = "tshark.exe" ascii wide
		$proc168 = "SUPERAntiSpyware.exe" ascii wide
		$proc169 = "firewall.exe" ascii wide
		$proc170 = "ashdisp.exe" ascii wide
		$proc171 = "rawshark.exe" ascii wide
		$proc172 = "vdtask.exe" ascii wide
		$proc173 = "firewall2004.exe" ascii wide
		$proc174 = "ashmaisv.exe" ascii wide
		$proc175 = "Ethereal.exe" ascii wide
		$proc176 = "asr.exe" ascii wide
		$proc177 = "firewallgui.exe" ascii wide
		$proc178 = "ashserv.exe" ascii wide
		$proc179 = "Tethereal.exe" ascii wide
		$proc180 = "NetguardLite.exe" ascii wide
		$proc181 = "gateway.exe" ascii wide
		$proc182 = "aswupdsv.exe" ascii wide
		$proc183 = "Windump.exe" ascii wide
		$proc184 = "nstzerospywarelite.exe" ascii wide
		$proc185 = "hpf_.exe" ascii wide
		$proc186 = "avastui.exe" ascii wide
		$proc187 = "Tcpdump.exe" ascii wide
		$proc188 = "cdinstx.exe" ascii wide
		$proc189 = "iface.exe" ascii wide
		$proc190 = "avastsvc.exe" ascii wide
		$proc191 = "Netcap.exe" ascii wide
		$proc192 = "cdas17.exe" ascii wide
		$proc193 = "invent.exe" ascii wide
		$proc194 = "Netmon.exe" ascii wide
		$proc195 = "fsrt.exe" ascii wide
		$proc196 = "ipcserver.exe" ascii wide
		$proc197 = "CV.exe" ascii wide
		$proc198 = "VSDesktop.exe" ascii wide
		$proc199 = "ipctray.exe" ascii wide
	condition:
		3 of them
}
rule Careto {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto generic malware signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:

		/* General */
		$name1 = "Careto" ascii wide
		$s_1 = "GetSystemReport" ascii wide
		$s_2 = "SystemReport.txt" ascii wide
		$s_3 = /URL_AUX\w*=/ ascii wide
		$s_4 = /CaretoPruebas.+release/

		/* Certificate */
		$sign_0 = "Sofia"
		$sign_1 = "TecSystem Ltd"
		$sign_2 = "<<<Obsolete>>>" wide

		/* Encryption keys */
		$rc4_1 = "!$7be&.Kaw-12[}" ascii wide
		$rc4_2 = "Caguen1aMar" ascii wide
		/* http://laboratorio.blogs.hispasec.com/2014/02/analisis-del-algoritmo-de-descifrado.html */
		$rc4_3 = {8d 85 86 8a 8f 80 88 83 8d 82 88 85 86 8f 8f 87 8d 82 83 82 8c 8e 83 8d 89 82 86 87 82 83 83 81}

		/* Decryption routine fragment */
		$dec_1 = {8b 4d 08 0f be 04 59 0f be 4c 59 01 2b c7 c1 e0 04 2b cf 0b c1 50 8d 85 f0 fe ff ff}
		$dec_2 = {8b 4d f8 8b 16 88 04 11 8b 06 41 89 4d f8 c6 04 01 00 43 3b 5d fc}

	condition:
		$name1 and (any of ($s_*)) or all of ($sign_*) or any of ($rc4_*) or all of ($dec_*)
}

rule Careto_CnC {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto CnC communication signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		$1 = "cgi-bin/commcgi.cgi" ascii wide
		$2 = "Group" ascii wide
		$3 = "Install" ascii wide
		$4 = "Bn" ascii wide
	condition:
		all of them
}

rule Careto_CnC_domains {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto known command and control domains"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		$1 = "linkconf.net" ascii wide nocase
		$2 = "redirserver.net" ascii wide nocase
		$3 = "swupdt.com" ascii wide nocase
	condition:
		any of them
}

rule Careto_OSX_SBD {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto OSX component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		/* XORed "/dev/null strdup() setuid(geteuid())" */
		$1 = {FF 16 64 0A 7E 1A 63 4D 21 4D 3E 1E 60 0F 7C 1A 65 0F 74 0B 3E 1C 7F 12}
	condition:
		all of them
}

rule Careto_SGH {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto SGH component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		$m1 = "PGPsdkDriver" ascii wide fullword
		$m2 = "jpeg1x32" ascii wide fullword
		$m3 = "SkypeIE6Plugin" ascii wide fullword
		$m4 = "CDllUninstall" ascii wide fullword
	condition:
		2 of them
}

rule dbgdetect_files : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"
	strings:
		$file1 = "syserdbgmsg" nocase ascii wide
		$file2 = "syserboot" nocase ascii wide
		$file3 = "SICE" nocase ascii wide
		$file4 = "NTICE" nocase ascii wide
	condition:
		2 of them
}

rule dbgdetect_funcs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$func1 = "IsDebuggerPresent"
		$func2 = "OutputDebugString"
		$func3 = "ZwQuerySystemInformation"
		$func4 = "ZwQueryInformationProcess"
		$func5 = "IsDebugged"
		$func6 = "NtGlobalFlags"
		$func7 = "CheckRemoteDebuggerPresent"
		$func8 = "SetInformationThread"
		$func9 = "DebugActiveProcess"

	condition:
		2 of them
}

rule dbgdetect_procs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$proc1 = "wireshark" nocase ascii wide
		$proc2 = "filemon" nocase ascii wide
		$proc3 = "procexp" nocase ascii wide
		$proc4 = "procmon" nocase ascii wide
		$proc5 = "regmon" nocase ascii wide
		$proc6 = "idag" nocase ascii wide
		$proc7 = "immunitydebugger" nocase ascii wide
		$proc8 = "ollydbg" nocase ascii wide
		$proc9 = "petools" nocase ascii wide

	condition:
		2 of them
}

rule GeorBotBinary
{
meta:
	Author = "AlienVault"
	reference = "https://www.alienvault.com/blogs/labs-research/georbot-botnet-a-cyber-espionage-campaign-against-georgian-government"
strings:
	$a = {63 72 ?? 5F 30 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C}

condition:
	all of them
}

rule GeorBotMemory
{
meta:
	Author = "AlienVault"
	reference = "https://www.alienvault.com/blogs/labs-research/georbot-botnet-a-cyber-espionage-campaign-against-georgian-government"
strings:
	$a = {53 4F 46 54 57 41 52 45 5C 00 4D 69 63 72 6F 73 6F 66 74 5C 00 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 00 52 75 6E 00 55 53 42 53 45 52 56}
	$b = {73 79 73 74 65 6D 33 32 5C 75 73 62 73 65 72 76 2E 65 78 65}
	$c = {5C 75 73 62 73 65 72 76 2E 65 78 65}
condition:
	$a and ($b or $c)
}

rule KINS_DLL_zeus {
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match default bot in KINS leaked dropper, Zeus"
	strings:
		// Network protocol
		$n1 = "%BOTID%" fullword
		$n2 = "%opensocks%" fullword
		$n3 = "%openvnc%" fullword
		$n4 = /Global\\(s|v)_ev/ fullword
		// Crypted strings
		$s1 = "\x72\x6E\x6D\x2C\x36\x7D\x76\x77"
		$s2 = "\x18\x04\x0F\x12\x16\x0A\x1E\x08\x5B\x11\x0F\x13"
		$s3 = "\x39\x1F\x01\x07\x15\x19\x1A\x33\x19\x0D\x1F"
		$s4 = "\x62\x6F\x71\x78\x63\x61\x7F\x69\x2D\x67\x79\x65"
		$s5 = "\x6F\x69\x7F\x6B\x61\x53\x6A\x7C\x73\x6F\x71"
	condition:
		all of ($n*) and 1 of ($s*)
}

rule KINS_dropper {
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match protocol, process injects and windows exploit present in KINS dropper"
	strings:
		// Network protocol
		$n1 = "tid=%d&ta=%s-%x" fullword
		$n2 = "fid=%d" fullword
		$n3 = "%[^.].%[^(](%[^)])" fullword
		// Injects
		$i0 = "%s [%s %d] 77 %s"
		$i01 = "Global\\%s%x"
		$i1 = "Inject::InjectProcessByName()"
		$i2 = "Inject::CopyImageToProcess()"
		$i3 = "Inject::InjectProcess()"
		$i4 = "Inject::InjectImageToProcess()"
		$i5 = "Drop::InjectStartThread()"
		// UAC bypass
		$uac1 = "ExploitMS10_092"
		$uac2 = "\\globalroot\\systemroot\\system32\\tasks\\" ascii wide
		$uac3 = "<RunLevel>HighestAvailable</RunLevel>" ascii wide
	condition:
		2 of ($n*) and 2 of ($i*) and 2 of ($uac*)
}

rule leverage_a
{
	meta:
		author = "earada@alienvault.com"
		version = "1.0"
		description = "OSX/Leverage.A"
		date = "2013/09"
	strings:
		$a1 = "ioreg -l | grep \"IOPlatformSerialNumber\" | awk -F"
		$a2 = "+:Users:Shared:UserEvent.app:Contents:MacOS:"
		$a3 = "rm '/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns'"
		$script1 = "osascript -e 'tell application \"System Events\" to get the hidden of every login item'"
		$script2 = "osascript -e 'tell application \"System Events\" to get the name of every login item'"
		$script3 = "osascript -e 'tell application \"System Events\" to get the path of every login item'"
		$properties = "serverVisible \x00"
	condition:
		all of them
}
rule sandboxdetect_misc : sandboxdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Sandbox detection tricks"

	strings:
		$sbxie1 = "sbiedll" nocase ascii wide

		// CWSandbox
		$prodid1 = "55274-640-2673064-23950" ascii wide
		$prodid2 = "76487-644-3177037-23510" ascii wide
		$prodid3 = "76487-337-8429955-22614" ascii wide

		$proc1 = "joeboxserver" ascii wide
		$proc2 = "joeboxcontrol" ascii wide
	condition:
		any of them
}
rule urausy_skype_dat {
	meta:
		author = "AlienVault Labs"
		description = "Yara rule to match against memory of processes infected by Urausy skype.dat"
	strings:
		$a = "skype.dat" ascii wide
		$b = "skype.ini" ascii wide
		$win1 = "CreateWindow"
		$win2 = "YIWEFHIWQ" ascii wide
		$desk1 = "CreateDesktop"
		$desk2 = "MyDesktop" ascii wide
	condition:
		$a and $b and (all of ($win*) or all of ($desk*))
}

rule vmdetect_misc : vmdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Virtual Machine detection tricks"

	strings:
		$vbox1 = "VBoxService" nocase ascii wide
		$vbox2 = "VBoxTray" nocase ascii wide
		$vbox3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase ascii wide
		$vbox4 = "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions" nocase ascii wide

		$wine1 = "wine_get_unix_file_name" ascii wide

		$vmware1 = "vmmouse.sys" ascii wide
		$vmware2 = "VMware Virtual IDE Hard Drive" ascii wide

		$miscvm1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase ascii wide
		$miscvm2 = "SYSTEM\\\\ControlSet001\\\\Services\\\\Disk\\\\Enum" nocase ascii wide

		// Drivers
		$vmdrv1 = "hgfs.sys" ascii wide
		$vmdrv2 = "vmhgfs.sys" ascii wide
		$vmdrv3 = "prleth.sys" ascii wide
		$vmdrv4 = "prlfs.sys" ascii wide
		$vmdrv5 = "prlmouse.sys" ascii wide
		$vmdrv6 = "prlvideo.sys" ascii wide
		$vmdrv7 = "prl_pv32.sys" ascii wide
		$vmdrv8 = "vpc-s3.sys" ascii wide
		$vmdrv9 = "vmsrvc.sys" ascii wide
		$vmdrv10 = "vmx86.sys" ascii wide
		$vmdrv11 = "vmnet.sys" ascii wide

		// SYSTEM\ControlSet001\Services
		$vmsrvc1 = "vmicheartbeat" ascii wide
		$vmsrvc2 = "vmicvss" ascii wide
		$vmsrvc3 = "vmicshutdown" ascii wide
		$vmsrvc4 = "vmicexchange" ascii wide
		$vmsrvc5 = "vmci" ascii wide
		$vmsrvc6 = "vmdebug" ascii wide
		$vmsrvc7 = "vmmouse" ascii wide
		$vmsrvc8 = "VMTools" ascii wide
		$vmsrvc9 = "VMMEMCTL" ascii wide
		$vmsrvc10 = "vmware" ascii wide
		$vmsrvc11 = "vmx86" ascii wide
		$vmsrvc12 = "vpcbus" ascii wide
		$vmsrvc13 = "vpc-s3" ascii wide
		$vmsrvc14 = "vpcuhub" ascii wide
		$vmsrvc15 = "msvmmouf" ascii wide
		$vmsrvc16 = "VBoxMouse" ascii wide
		$vmsrvc17 = "VBoxGuest" ascii wide
		$vmsrvc18 = "VBoxSF" ascii wide
		$vmsrvc19 = "xenevtchn" ascii wide
		$vmsrvc20 = "xennet" ascii wide
		$vmsrvc21 = "xennet6" ascii wide
		$vmsrvc22 = "xensvc" ascii wide
		$vmsrvc23 = "xenvdb" ascii wide

		// Processes
		$miscproc1 = "vmware2" ascii wide
		$miscproc2 = "vmount2" ascii wide
		$miscproc3 = "vmusrvc" ascii wide
		$miscproc4 = "vmsrvc" ascii wide
		$miscproc5 = "vboxservice" ascii wide
		$miscproc6 = "vboxtray" ascii wide
		$miscproc7 = "xenservice" ascii wide

		$vmware_mac_1a = "00-05-69"
		$vmware_mac_1b = "00:05:69"
		$vmware_mac_2a = "00-50-56"
		$vmware_mac_2b = "00:50:56"
		$vmware_mac_3a = "00-0C-29"
		$vmware_mac_3b = "00:0C:29"
		$vmware_mac_4a = "00-1C-14"
		$vmware_mac_4b = "00:1C:14"
		$virtualbox_mac_1a = "08-00-27"
		$virtualbox_mac_1b = "08:00:27"

	condition:
		2 of them
}

rule oceanlotus_xor_decode
{
        meta:
               author = "AlienVault Labs"
               type = "malware"
               description = "OceanLotus XOR decode function"
               reference = "https://www.alienvault.com/blogs/labs-research/oceanlotus-for-os-x-an-application-bundle-pretending-to-be-an-adobe-flash-update"
    strings:
        $xor_decode = { 89 D2 41 8A ?? ?? [0-1] 32 0? 88 ?? FF C2 [0-1] 39 ?A [0-1] 0F 43 D? 4? FF C? 48 FF C? [0-1] FF C? 75 E3 }
    condition:
        $xor_decode
}

rule oceanlotus_constants
{
        meta:
               author = "AlienVault Labs"
               type = "malware"
               description = "OceanLotus constants"
               reference = "https://www.alienvault.com/blogs/labs-research/oceanlotus-for-os-x-an-application-bundle-pretending-to-be-an-adobe-flash-update"
    strings:
        $c1 = { 3A 52 16 25 11 19 07 14 3D 08 0F }
        $c2 = { 0F 08 3D 14 07 19 11 25 16 52 3A }
    condition:
        any of them
}

rule CaptainWord {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/cyber-espionage-campaign-against-the-uyghur-community-targeting-macosx-syst"
        

    strings:

         $header = {D0 CF 11 E0 A1 B1 1A E1}

         $author = {00 00 00 63 61 70 74 61 69 6E 00}

    condition:

         $header at 0 and $author

}


rule Hangover2_Keylogger

{
  meta:
    author = "Alienvault Labs"
    reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
  strings:

    $a = "iconfall" wide ascii

    $b = "/c ipconfig /all > "" wide ascii

    $c = "Global\{CHKAJESKRB9-35NA7-94Y436G37KGT}" wide ascii

  condition:

    all of them

}

rule Hangover_ron_babylon
{
  meta:
    author = "Alienvault Labs"
    reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"

  strings:
    $a = "Content-Disposition: form-data; name=\"uploaddir\""
    $b1 = "MBVDFRESCT"
    $b2 = "EMSCBVDFRT"
    $b3 = "EMSFRTCBVD"
    $b4= "sendFile"
    $b5 = "BUGMAAL"
    $b6 = "sMAAL"
    $b7 = "SIMPLE"
    $b8 = "SPLIME"
    $b9 = "getkey.php"
    $b10 = "MBVDFRESCT"
    $b11 = "DSMBVCTFRE"
    $b12 = "MBESCVDFRT"
    $b13 = "TCBFRVDEMS"
    $b14 = "DEMOMAKE"
    $b15 = "DEMO"
    $b16 = "UPHTTP"
    

    $c1 = "F39D45E70395ABFB8D8D2BFFC8BBD152"
    $c2 = "90B452BFFF3F395ABDC878D8BEDBD152"
    $c3 = "FFF3F395A90B452BB8BEDC878DDBD152"
    $c4 = "5A9DCB8FFF3F02B8B45BE39D152"
    $c5 = "5A902B8B45BEDCB8FFF3F39D152"
    $c6 = "78DDB5A902BB8FFF3F398B45BEDCD152"
    $c7 = "905ABEB452BFFFBDC878D83F39DBD152"
    $c8 = "D2BFFC8BBD152F3B8D89D45E70395ABF"
    $c9 = "8765F3F395A90B452BB8BEDC878"
    $c10 = "90ABDC878D8BEDBB452BFFF3F395D152"
    $c11 = "F12BDC94490B452AA8AEDC878DCBD187"
    
  condition:
    $a and (1 of ($b*) or 1 of ($c*))
    
}

rule Hangover_Fuddol {
    meta:
        author = "Alienvault Labs"
        referemce = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a = "\\Http downloader(fud)"
        $b = "Fileexists"
    condition:
        all of them

}

rule Hangover_UpdateEx {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "UpdateEx"
        $a2 = "VBA6.DLL"
        $a3 = "MainEx"
        $a4 = "GetLogs"
        $a5 = "ProMan"
        $a6 = "RedMod"
        
    condition:
        all of them

}

rule Hangover_Tymtin_Degrab {
    meta:
         author = "Alienvault Labs"
         reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "&dis=no&utp=op&mfol="
        $a2 = "value1=1&value2=2"
        
    condition:
        all of them

}


rule Hangover_Smackdown_Downloader {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "DownloadComplete"
        $a2 = "DownloadProgress"
        $a3 = "DownloadError"
        $a4 = "UserControl"
        $a5 = "MSVBVM60.DLL"

        $b1 = "syslide"
        $b2 = "frmMina"
        $b3 = "Soundsman"
        $b4 = "New_upl"
        $b5 = "MCircle"
        $b6 = "shells_DataArrival"
        
    condition:
        3 of ($a*) and 1 of ($b*)

}


rule Hangover_Vacrhan_Downloader {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "pranVacrhan"
        $a2 = "VBA6.DLL"
        $a3 = "Timer1"
        $a4 = "Timer2"
        $a5 = "IsNTAdmin"
        
    condition:
        all of them

}


rule Hangover_Smackdown_various {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "pranVacrhan"
        $a2 = "NaramGaram"
        $a3 = "vampro"
        $a4 = "AngelPro"
        
        $b1 = "VBA6.DLL"
        $b2 = "advpack"
        $b3 = "IsNTAdmin"
        
        
    condition:
        1 of ($a*) and all of ($b*)

}

rule Hangover_Foler {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "\\MyHood"
        $a2 = "UsbP"
        $a3 = "ID_MON"
        
    condition:
        all of them

}

rule Hangover_Appinbot {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "CreateToolhelp32Snapshot"
        $a2 = "Process32First"
        $a3 = "Process32Next"
        $a4 = "FIDR/"
        $a5 = "SUBSCRIBE %d"
        $a6 = "CLOSE %d"
        
    condition:
        all of them

}

rule Hangover_Linog {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "uploadedfile"
        $a2 = "Error in opening a file.."
        $a3 = "The file could not be opened"
        $a4 = "%sContent-Disposition: form-data; name=\"%s\";filename=\"%s\""

    condition:
        all of them

}


rule Hangover_Iconfall {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "iconfall"
        $a2 = "78DDB5A902BB8FFF3F398B45BEDCD152"
        
    condition:
        all of them

}


rule Hangover_Deksila {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "WinInetGet/0.1"
        $a2 = "dekstop2007.ico"
        $a3 = "mozila20"
        
    condition:
        all of them

}

rule Hangover_Auspo {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV2)"
        $a2 = "POWERS"
        $a3 = "AUSTIN"
        
    condition:
        all of them

}

rule Hangover_Slidewin {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "[NumLock]"
        $a2 = "[ScrlLock]"
        $a3 = "[LtCtrl]"
        $a4 = "[RtCtrl]"
        $a5 = "[LtAlt]"
        $a6 = "[RtAlt]"
        $a7 = "[HomePage]"
        $a8 = "[MuteOn/Off]"
        $a9 = "[VolDn]"
        $a10 = "[VolUp]"
        $a11 = "[Play/Pause]"
        $a12 = "[MailBox]"
        $a14 = "[Calc]"
        $a15 = "[Unknown]"
        
    condition:
        all of them

}


rule Hangover_Gimwlog {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "file closed---------------------"
        $a2 = "new file------------------"
        $a3 = "md C:\\ApplicationData\\Prefetch\\"
        
    condition:
        all of them

}


rule Hangover_Gimwup {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "=======inside while==========="
        $a2 = "scan finished"
        $a3 = "logFile.txt"
        
    condition:
        all of them

}

rule Hangover2_Downloader {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"

  strings:

    $a = "WinInetGet/0.1" wide ascii

    $b = "Excep while up" wide ascii

    $c = "&file=" wide ascii

    $d = "&str=" wide ascii

    $e = "?cn=" wide ascii

  condition:

    all of them
}

rule Hangover2_stealer {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"

  strings:

    $a = "MyWebClient" wide ascii

    $b = "Location: {[0-9]+}" wide ascii

    $c = "[%s]:[C-%s]:[A-%s]:[W-%s]:[S-%d]" wide ascii

  condition:

    all of them
}

rule Hangover2_backdoor_shell {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"

  strings:

    $a = "Shell started at: " wide ascii

    $b = "Shell closed at: " wide ascii

    $c = "Shell is already closed!" wide ascii

    $d = "Shell is not Running!" wide ascii

  condition:

    all of them
}

 