private rule APT3102Code : APT3102 Family 
{
    meta:
        description = "3102 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $setupthread = { B9 02 07 00 00 BE ?? ?? ?? ?? 8B F8 6A 00 F3 A5 }
  
    condition:
        any of them
}

private rule APT3102Strings : APT3102 Family
{
    meta:
        description = "3102 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "rundll32_exec.dll\x00Update"
        // this is in the encrypted code - shares with 9002 variant
        //$ = "POST http://%ls:%d/%x HTTP/1.1"
        
    condition:
       any of them
}


private rule APT9002Code : APT9002 Family 
{
    meta:
        description = "9002 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        // start code block
        $ = { B9 7A 21 00 00 BE ?? ?? ?? ?? 8B F8 ?? ?? ?? F3 A5 }
        // decryption from other variant with multiple start threads
        $ = { 8A 14 3E 8A 1C 01 32 DA 88 1C 01 8B 54 3E 04 40 3B C2 72 EC }
  
    condition:
        any of them
}

private rule APT9002Strings : APT9002 Family
{
    meta:
        description = "9002 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "POST http://%ls:%d/%x HTTP/1.1"
        $ = "%%TEMP%%\\%s_p.ax" wide ascii
        $ = "%TEMP%\\uid.ax" wide ascii
        $ = "%%TEMP%%\\%s.ax" wide ascii
        // also triggers on surtr $ = "mydll.dll\x00DoWork"
        $ = "sysinfo\x00sysbin01"
        $ = "\\FlashUpdate.exe"
        
    condition:
       any of them
}


rule APT_NGO_wuaclt
{
  strings:
    $a = "%%APPDATA%%\\Microsoft\\wuauclt\\wuauclt.dat"
    $b = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    $c = "/news/show.asp?id%d=%d"
    
	$d = "%%APPDATA%%\\Microsoft\\wuauclt\\"
	$e = "0l23kj@nboxu"
	
	$f = "%%s.asp?id=%%d&Sid=%%d"
	$g = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SP Q%%d)"
	$h = "Cookies: UseID=KGIOODAOOK%%s"

  condition:
    ($a and $b and $c) or ($d and $e) or ($f and $g and $h)
}
rule APT_NGO_wuaclt_PDF
{
	strings:
		$pdf  = "%PDF" nocase
		$comment = {3C 21 2D 2D 0D 0A 63 57 4B 51 6D 5A 6C 61 56 56 56 56 56 56 56 56 56 56 56 56 56 63 77 53 64 63 6A 4B 7A 38 35 6D 37 4A 56 6D 37 4A 46 78 6B 5A 6D 5A 6D 52 44 63 5A 58 41 73 6D 5A 6D 5A 7A 42 4A 31 79 73 2F 4F 0D 0A}
	
	condition:
		$pdf at 0 and $comment in (0..200)
}

rule SNOWGLOBE_Babar_Malware 
{
    meta:
        description = "Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe"
        author = "Florian Roth"
        reference = "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
        date = "2015/02/18"
        hash = "27a0a98053f3eed82a51cdefbdfec7bb948e1f36"
        score = 80

    strings:
        $mz = { 4d 5a }
        $z0 = "admin\\Desktop\\Babar64\\Babar64\\obj\\DllWrapper" ascii fullword
        $z1 = "User-Agent: Mozilla/4.0 (compatible; MSI 6.0;" ascii fullword
        $z2 = "ExecQueryFailled!" fullword ascii
        $z3 = "NBOT_COMMAND_LINE" fullword
        $z4 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]" fullword

        $s1 = "/s /n %s \"%s\"" fullword ascii
        $s2 = "%%WINDIR%%\\%s\\%s" fullword ascii
        $s3 = "/c start /wait " fullword ascii
        $s4 = "(D;OICI;FA;;;AN)(A;OICI;FA;;;BG)(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)" ascii

        $x1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii
        $x2 = "%COMMON_APPDATA%" fullword ascii
        $x4 = "CONOUT$" fullword ascii
        $x5 = "cmd.exe" fullword ascii
        $x6 = "DLLPATH" fullword ascii

    condition:
        ( $mz at 0 ) and filesize < 1MB and
        (( 1 of ($z*) and 1 of ($x*) ) or( 3 of ($s*) and 4 of ($x*) ))
}
private rule BangatCode : Bangat Family 
{
    meta:
        description = "Bangat code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // dec [ebp + procname], push eax, push edx, call get procaddress
        $ = { FE 4D ?? 8D 4? ?? 50 5? FF }
    
    condition:
        any of them
}

private rule BangatStrings : Bangat Family
{
    meta:
        description = "Bangat Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $lib1 = "DreatePipe"
        $lib2 = "HetSystemDirectoryA"
        $lib3 = "SeleaseMutex"
        $lib4 = "DloseWindowStation"
        $lib5 = "DontrolService"
        $file = "~hhC2F~.tmp"
        $mc = "~_MC_3~"

    condition:
       all of ($lib*) or $file or $mc
}


private rule BoousetCode : Boouset Family 
{
    meta:
        description = "Boouset code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $boousetdat = { C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }
        
    condition:
        any of them
}

private rule BoousetStrings : Boouset Family
{
    meta:
        description = "Boouset Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        //$s1 = "Q\x00\x00\x00\x00W\x00\x00\x00\x00E\x00\x00\x00\x00R\x00\x00\x00\x00T\x00\x00\x00\x00Y\x00\x00\x00\x00"
        //$s2 = "A\x00\x00\x00\x00S\x00\x00\x00\x00D\x00\x00\x00\x00F\x00\x00\x00\x00G\x00\x00\x00\x00H"
        //$s3 = "Z\x00\x00\x00\x00X\x00\x00\x00\x00C\x00\x00\x00\x00V\x00\x00\x00\x00B\x00\x00\x00\x00N\x00\x00\x00\x00"
        $s4 = "\\~Z8314.tmp"
        $s5 = "hulee midimap" wide ascii
        
    condition:
       any of them
}

private rule ComfooCode : Comfoo Family 
{
    meta:
        description = "Comfoo code features"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $resource = { 6A 6C 6A 59 55 E8 01 FA FF FF }
  
    condition:
        any of them
}

private rule ComfooStrings : Comfoo Family
{
    meta:
        description = "Comfoo Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $ = "fefj90"
        $ = "iamwaitingforu653890"
        $ = "watchevent29021803"
        $ = "THIS324NEWGAME"
        $ = "ms0ert.temp"
        $ = "\\mstemp.temp"
        
    condition:
       any of them
}

private rule CookiesStrings : Cookies Family
{
    meta:
        description = "Cookies Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $zip1 = "ntdll.exePK"
        $zip2 = "AcroRd32.exePK"
        $zip3 = "Setup=ntdll.exe\x0d\x0aSilent=1\x0d\x0a"
        $zip4 = "Setup=%temp%\\AcroRd32.exe\x0d\x0a"
        $exe1 = "Leave GetCommand!"
        $exe2 = "perform exe success!"
        $exe3 = "perform exe failure!"
        $exe4 = "Entry SendCommandReq!"
        $exe5 = "Reqfile not exist!"
        $exe6 = "LeaveDealUpfile!"
        $exe7 = "Entry PostData!"
        $exe8 = "Leave PostFile!"
        $exe9 = "Entry PostFile!"
        $exe10 = "\\unknow.zip" wide ascii
        $exe11 = "the url no respon!"
        
    condition:
      (2 of ($zip*)) or (2 of ($exe*))
}

private rule cxpidCode : cxpid Family 
{
    meta:
        description = "cxpid code features"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
    
    strings:
        $entryjunk = { 55 8B EC B9 38 04 00 00 6A 00 6A 00 49 75 F9 }
    
    condition:
        any of them
}

private rule cxpidStrings : cxpid Family
{
    meta:
        description = "cxpid Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "/cxpid/submit.php?SessionID="
        $ = "/cxgid/"
        $ = "E21BC52BEA2FEF26D005CF"
        $ = "E21BC52BEA39E435C40CD8"
        $ = "                   -,L-,O+,Q-,R-,Y-,S-"
        
    condition:
       any of them
}

private rule EnfalCode : Enfal Family 
{
    meta:
        description = "Enfal code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        // mov al, 20h; sub al, bl; add [ebx+esi], al; push esi; inc ebx; call edi; cmp ebx, eax
        $decrypt = { B0 20 2A C3 00 04 33 56 43 FF D7 3B D8 }
        
    condition:
        any of them
}

private rule EnfalStrings : Enfal Family
{
    meta:
        description = "Enfal Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "D:\\work\\\xe6\xba\x90\xe5\x93\xa5\xe5\x85\x8d\xe6\x9d\x80\\tmp\\Release\\ServiceDll.pdb"
        $ = "e:\\programs\\LuridDownLoader"
        $ = "LuridDownloader for Falcon"
        $ = "DllServiceTrojan"
        $ = "\\k\\\xe6\xa1\x8c\xe8\x9d\xa2\\"
        $ = "EtenFalcon\xef\xbc\x88\xe4\xbf\xae\xe6\x94\xb9\xef\xbc\x89"
        $ = "Madonna\x00Jesus"
        $ = "/iupw82/netstate"
        $ = "fuckNodAgain"
        $ = "iloudermao"
        $ = "Crpq2.cgi"
        $ = "Clnpp5.cgi"
        $ = "Dqpq3ll.cgi"
        $ = "dieosn83.cgi"
        $ = "Rwpq1.cgi"
        $ = "/Ccmwhite"
        $ = "/Cmwhite"
        $ = "/Crpwhite"
        $ = "/Dfwhite"
        $ = "/Query.txt"
        $ = "/Ufwhite"
        $ = "/cgl-bin/Clnpp5.cgi"
        $ = "/cgl-bin/Crpq2.cgi"
        $ = "/cgl-bin/Dwpq3ll.cgi"
        $ = "/cgl-bin/Owpq4.cgi"
        $ = "/cgl-bin/Rwpq1.cgi"
        $ = "/trandocs/mm/"
        $ = "/trandocs/netstat"
        $ = "NFal.exe"
        $ = "LINLINVMAN"
        $ = "7NFP4R9W"
        
    condition:
        any of them
}

private rule EzcobStrings : Ezcob Family
{
    meta:
        description = "Ezcob Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "\x12F\x12F\x129\x12E\x12A\x12E\x12B\x12A\x12-\x127\x127\x128\x123\x12"
        $ = "\x121\x12D\x128\x123\x12B\x122\x12E\x128\x12-\x12B\x122\x123\x12D\x12"
        $ = "Ezcob" wide ascii
        $ = "l\x12i\x12u\x122\x120\x121\x123\x120\x124\x121\x126"
        $ = "20110113144935"
        
    condition:
       any of them
}

rule ws_f0xy_downloader {
  meta:
    description = "f0xy malware downloader"
    author = "Nick Griffin (Websense)"

  strings:
    $mz="MZ"
    $string1="bitsadmin /transfer"
    $string2="del rm.bat"
    $string3="av_list="
  
  condition:
    ($mz at 0) and (all of ($string*))
}
private rule HTMLVariant : FakeM Family HTML Variant
{
	meta:
		description = "Identifier for html variant of FAKEM"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
	
	strings:
		// decryption loop
		$s1 = { 8B 55 08 B9 00 50 00 00 8D 3D ?? ?? ?? 00 8B F7 AD 33 C2 AB 83 E9 04 85 C9 75 F5 }
		//mov byte ptr [ebp - x] y, x: 0x10-0x1 y: 0-9,A-F
		$s2 = { C6 45 F? (3?|4?) }

	condition:
		$s1 and #s2 == 16

}

//todo: need rules for other variants
rule FakeM : Family
{
	meta:
		description = "FakeM"
		author = "Katie Kleemola"
		last_updated = "2014-07-03"
	
	condition:
		HTMLVariant


}

rule FAKEMhtml : Variant
{
	meta:
		description = "Rule for just the HTML Variant"
		author = "Katie Kleemola"
		last_updated = "2014-07-10"
	
	condition:
		HTMLVariant
}
private rule FavoriteCode : Favorite Family 
{
    meta:
        description = "Favorite code features"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
    
    strings:
        // standard string hiding
        $ = { C6 45 ?? 3B C6 45 ?? 27 C6 45 ?? 34 C6 45 ?? 75 C6 45 ?? 6B C6 45 ?? 6C C6 45 ?? 3B C6 45 ?? 2F }
        $ = { C6 45 ?? 6F C6 45 ?? 73 C6 45 ?? 73 C6 45 ?? 76 C6 45 ?? 63 C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 }
    
    condition:
        any of them
}

private rule FavoriteStrings : Favorite Family
{
    meta:
        description = "Favorite Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    strings:
        $string1 = "!QAZ4rfv"
        $file1 = "msupdater.exe"
        $file2 = "FAVORITES.DAT"
        
    condition:
       any of ($string*) or all of ($file*)
}

rule GeorBotBinary
{
	strings:
		$a = {63 72 ?? 5F 30 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C}

	condition:
		all of them
}
rule GeorBotMemory
{
	strings:
		$a = {53 4F 46 54 57 41 52 45 5C 00 4D 69 63 72 6F 73 6F 66 74 5C 00 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 00 52 75 6E 00 55 53 42 53 45 52 56}
		$b = {73 79 73 74 65 6D 33 32 5C 75 73 62 73 65 72 76 2E 65 78 65}
		$c = {5C 75 73 62 73 65 72 76 2E 65 78 65}
	condition:
		$a and ($b or $c)
}
private rule GlassesCode : Glasses Family 
{
    meta:
        description = "Glasses code features"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
        
    strings:
        $ = { B8 AB AA AA AA F7 E1 D1 EA 8D 04 52 2B C8 }
        $ = { B8 56 55 55 55 F7 E9 8B 4C 24 1C 8B C2 C1 E8 1F 03 D0 49 3B CA }
        
    condition:
        any of them
}

private rule GlassesStrings : Glasses Family
{
    meta:
        description = "Strings used by Glasses"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
        
    strings:
        $ = "thequickbrownfxjmpsvalzydg"
        $ = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0; %s.%s)"
        $ = "\" target=\"NewRef\"></a>"
 
    condition:
        all of them

}

rule Hangover_ron_babylon
{
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
    strings:
        $a = "\\Http downloader(fud)"
        $b = "Fileexists"
    condition:
        all of them

}

rule Hangover_UpdateEx {
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
    strings:
        $a1 = "&dis=no&utp=op&mfol="
        $a2 = "value1=1&value2=2"
        
    condition:
        all of them

}


rule Hangover_Smackdown_Downloader {
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
    strings:
        $a1 = "\\MyHood"
        $a2 = "UsbP"
        $a3 = "ID_MON"
        
    condition:
        all of them

}

rule Hangover_Appinbot {
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
    strings:
        $a1 = "uploadedfile"
        $a2 = "Error in opening a file.."
        $a3 = "The file could not be opened"
        $a4 = "%sContent-Disposition: form-data; name=\"%s\";filename=\"%s\""

    condition:
        all of them

}


rule Hangover_Iconfall {
    strings:
        $a1 = "iconfall"
        $a2 = "78DDB5A902BB8FFF3F398B45BEDCD152"
        
    condition:
        all of them

}


rule Hangover_Deksila {
    strings:
        $a1 = "WinInetGet/0.1"
        $a2 = "dekstop2007.ico"
        $a3 = "mozila20"
        
    condition:
        all of them

}

rule Hangover_Auspo {
    strings:
        $a1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV2)"
        $a2 = "POWERS"
        $a3 = "AUSTIN"
        
    condition:
        all of them

}

rule Hangover_Slidewin {
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
    strings:
        $a1 = "file closed---------------------"
        $a2 = "new file------------------"
        $a3 = "md C:\\ApplicationData\\Prefetch\\"
        
    condition:
        all of them

}


rule Hangover_Gimwup {
    strings:
        $a1 = "=======inside while==========="
        $a2 = "scan finished"
        $a3 = "logFile.txt"
        
    condition:
        all of them

}

rule Hangover2_Downloader {

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

  strings:

    $a = "MyWebClient" wide ascii

    $b = "Location: {[0-9]+}" wide ascii

    $c = "[%s]:[C-%s]:[A-%s]:[W-%s]:[S-%d]" wide ascii

  condition:

    all of them
}

rule Hangover2_backdoor_shell {

  strings:

    $a = "Shell started at: " wide ascii

    $b = "Shell closed at: " wide ascii

    $c = "Shell is already closed!" wide ascii

    $d = "Shell is not Running!" wide ascii

  condition:

    all of them
}

rule Hangover2_Keylogger {

  strings:

    $a = "iconfall" wide ascii

    $b = "/c ipconfig /all > " wide ascii

    $c = "Global\\{CHKAJESKRB9-35NA7-94Y436G37KGT}" wide ascii

  condition:

    all of them
}

private rule iexpl0reCode : iexpl0ree Family 
{
    meta:
        description = "iexpl0re code features"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
        
    strings:
        $ = { 47 83 FF 64 0F 8C 6D FF FF FF 33 C0 5F 5E 5B C9 C3 }
        $ = { 80 74 0D A4 44 41 3B C8 7C F6 68 04 01 00 00 }
        $ = { 8A C1 B2 07 F6 EA 30 04 31 41 3B 4D 10 7C F1 }
        $ = { 47 83 FF 64 0F 8C 79 FF FF FF 33 C0 5F 5E 5B C9 C3 }
        // 88h decrypt
        $ = { 68 88 00 00 00 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        $ = { BB 88 00 00 00 53 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        
    condition:
        any of them
}

private rule iexpl0reStrings : iexpl0re Family
{
    meta:
        description = "Strings used by iexpl0re"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
        
    strings:
        $ = "%USERPROFILE%\\IEXPL0RE.EXE"
        $ = "\"<770j (("
        $ = "\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IEXPL0RE.LNK"
        $ = "\\Documents and Settings\\%s\\Application Data\\Microsoft\\Internet Explorer\\IEXPL0RE.EXE"
        $ = "LoaderV5.dll"
        // stage 2
        $ = "POST /index%0.9d.asp HTTP/1.1"
        $ = "GET /search?n=%0.9d&"
        $ = "DUDE_AM_I_SHARP-3.14159265358979x6.626176"
        $ = "WHO_A_R_E_YOU?2.99792458x1.25663706143592"
        $ = "BASTARD_&&_BITCHES_%0.8x"
        $ = "c:\\bbb\\eee.txt"
        
    condition:
        any of them

}

private rule IMulerCode : IMuler Family 
{
    meta:
        description = "IMuler code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_tmpSpotlight = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 53 70 6F }
        $L4_TMPAAABBB = { C7 ?? ?? ?? ?? ?? 54 4D 50 41 C7 ?? ?? ?? ?? ?? 41 41 42 42 }
        $L4_FILEAGENTVer = { C7 ?? 46 49 4C 45 C7 ?? 04 41 47 45 4E }
        $L4_TMP0M34JDF8 = { C7 ?? ?? ?? ?? ?? 54 4D 50 30 C7 ?? ?? ?? ?? ?? 4D 33 34 4A }
        $L4_tmpmdworker = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 2E 6D 64 }
        
    condition:
        any of ($L4*)
}

private rule IMulerStrings : IMuler Family
{
    meta:
        description = "IMuler Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    strings:
        $ = "/cgi-mac/"
        $ = "xnocz1"
        $ = "checkvir.plist"
        $ = "/Users/apple/Documents/mac back"
        $ = "iMuler2"
        $ = "/Users/imac/Desktop/macback/"
        $ = "xntaskz.gz"
        $ = "2wmsetstatus.cgi"
        $ = "launch-0rp.dat"
        $ = "2wmupload.cgi"
        $ = "xntmpz"
        $ = "2wmrecvdata.cgi"
        $ = "xnorz6"
        $ = "2wmdelfile.cgi"
        $ = "/LanchAgents/checkvir"
        $ = "0PERA:%s"
        $ = "/tmp/Spotlight"
        $ = "/tmp/launch-ICS000"
        
    condition:
        any of them
}


private rule Insta11Code : Insta11 Family 
{
    meta:
        description = "Insta11 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
    
    strings:
        // jmp $+5; push 423h
        $jumpandpush = { E9 00 00 00 00 68 23 04 00 00 }
    
    condition:
        any of them
}

private rule Insta11Strings : Insta11 Family
{
    meta:
        description = "Insta11 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "XTALKER7"
        $ = "Insta11 Microsoft" wide ascii
        $ = "wudMessage"
        $ = "ECD4FC4D-521C-11D0-B792-00A0C90312E1"
        $ = "B12AE898-D056-4378-A844-6D393FE37956"
        
    condition:
       any of them
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

private rule LuckyCatCode : LuckyCat Family 
{
    meta:
        description = "LuckyCat code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $xordecrypt = { BF 0F 00 00 00 F7 F7 ?? ?? ?? ?? 32 14 39 80 F2 7B }
        $dll = { C6 ?? ?? ?? 64 C6 ?? ?? ?? 6C C6 ?? ?? ?? 6C }
        $commonletters = { B? 63 B? 61 B? 73 B? 65 }
        
    condition:
        $xordecrypt or ($dll and $commonletters)
}

private rule LuckyCatStrings : LuckyCat Family
{
    meta:
        description = "LuckyCat Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $xorencrypted = { 77 76 75 7B 7A 79 78 7F 7E 7D 7C 73 72 71 70 }
        $tempvbs = "%s\\~temp.vbs"
        $countphp = "count.php\x00"
        $trojanname = "/WMILINK=.*TrojanName=/"
        $tmpfile = "d0908076343423d3456.tmp"
        $dirfile = "cmd /c dir /s /a C:\\\\ >'+tmpfolder+'\\\\C.tmp"
        $ipandmac = "objIP.DNSHostName+'_'+objIP.MACAddress.split(':').join('')+'_'+addinf+'@')"
        
    condition:
       any of them
}
private rule LURK0Header : Family LURK0 {
	meta:
		description = "5 char code for LURK0"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = { C6 [5] 4C C6 [5] 55 C6 [5] 52 C6 [5] 4B C6 [5] 30 }

	condition:
		any of them
}

private rule CCTV0Header : Family CCTV0 {
        meta:  
		description = "5 char code for LURK0"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"

	strings:
		//if its just one char a time
		$ = { C6 [5] 43 C6 [5] 43 C6 [5] 54 C6 [5] 56 C6 [5] 30 }
		// bit hacky but for when samples dont just simply mov 1 char at a time
		$ = { B0 43 88 [3] 88 [3] C6 [3] 54 C6 [3] 56 [0-12] (B0 30 | C6 [3] 30) }

	condition:
		any of them
}

private rule SharedStrings : Family {
	meta:
		description = "Internal names found in LURK0/CCTV0 samples"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"
	
	strings:
		// internal names
		$i1 = "Butterfly.dll"
		$i2 = /\\BT[0-9.]+\\ButterFlyDLL\\/
		$i3 = "ETClientDLL"

		// dbx
		$d1 = "\\DbxUpdateET\\" wide
		$d2 = "\\DbxUpdateBT\\" wide
		$d3 = "\\DbxUpdate\\" wide
		
		// other folders
		$mc1 = "\\Micet\\"

		// embedded file names
		$n1 = "IconCacheEt.dat" wide
		$n2 = "IconConfigEt.dat" wide

		$m1 = "\x00\x00ERXXXXXXX\x00\x00" wide
		$m2 = "\x00\x00111\x00\x00" wide
		$m3 = "\x00\x00ETUN\x00\x00" wide
		$m4 = "\x00\x00ER\x00\x00" wide

	condition:
		any of them //todo: finetune this

}

private rule MacControlCode : MacControl Family 
{
    meta:
        description = "MacControl code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-17"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_Accept = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 3A 20 }
        $L4_AcceptLang = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 2D 4C }
        $L4_Pragma = { C7 ?? 50 72 61 67 C7 ?? 04 6D 61 3A 20 }
        $L4_Connection = { C7 ?? 43 6F 6E 6E C7 ?? 04 65 63 74 69 }
        $GEThgif = { C7 ?? 47 45 54 20 C7 ?? 04 2F 68 2E 67 }
        
    condition:
        all of ($L4*) or $GEThgif
}

private rule MacControlStrings : MacControl Family
{
    meta:
        description = "MacControl Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-17"
        
    strings:
        $ = "HTTPHeadGet"
        $ = "/Library/launched"
        $ = "My connect error with no ip!"
        $ = "Send File is Failed"
        $ = "****************************You Have got it!****************************"
        
    condition:
        any of them
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

private rule MirageStrings : Mirage Family
{
    meta:
        description = "Mirage Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "Neo,welcome to the desert of real." wide ascii
        $ = "/result?hl=en&id=%s"
        
    condition:
       any of them
}

private rule MongalCode : Mongal Family 
{
    meta:
        description = "Mongal code features"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
    
    strings:
        // gettickcount value checking
        $ = { 8B C8 B8 D3 4D 62 10 F7 E1 C1 EA 06 2B D6 83 FA 05 76 EB }
        
    condition:
        any of them
}

private rule MongalStrings : Mongal Family
{
    meta:
        description = "Mongal Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    strings:
        $ = "NSCortr.dll"
        $ = "NSCortr1.dll"
        $ = "Sina.exe"
        
    condition:
        any of them
}
private rule NaikonCode : Naikon Family 
{
    meta:
        description = "Naikon code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $ = { 0F AF C1 C1 E0 1F } // imul eax, ecx; shl eah, 1fh
        $ = { 35 5A 01 00 00} // xor eax, 15ah
        $ = { 81 C2 7F 14 06 00 } // add edx, 6147fh
    
    condition:
        all of them
}

private rule NaikonStrings : Naikon Family
{
    meta:
        description = "Naikon Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "NOKIAN95/WEB"
        $ = "/tag=info&id=15"
        $ = "skg(3)=&3.2d_u1"
        $ = "\\Temp\\iExplorer.exe"
        $ = "\\Temp\\\"TSG\""
        
    condition:
       any of them
}
private rule nAspyUpdateCode : nAspyUpdate Family 
{
    meta:
        description = "nAspyUpdate code features"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop in dropper
        $ = { 8A 54 24 14 8A 01 32 C2 02 C2 88 01 41 4E 75 F4 }
        
    condition:
        any of them
}

private rule nAspyUpdateStrings : nAspyUpdate Family
{
    meta:
        description = "nAspyUpdate Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    strings:
        $ = "\\httpclient.txt"
        $ = "password <=14"
        $ = "/%ldn.txt"
        $ = "Kill You\x00"
        
    condition:
        any of them
}
//will match both exe and dll components
private rule NetTravExports : NetTraveler Family {

	meta:
		description = "Export names for dll component"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
	
	strings:
		//dll component exports
		$ = "?InjectDll@@YAHPAUHWND__@@K@Z"
		$ = "?UnmapDll@@YAHXZ"
		$ = "?g_bSubclassed@@3HA"
		
	condition:
		any of them
}

private rule NetTravStrings : NetTraveler Family {


	meta:
        	description = "Identifiers for NetTraveler DLL"
		author = "Katie Kleemola"
        	last_updated = "2014-05-20"

	strings:
		//network strings
		$ = "?action=updated&hostid="
		$ = "travlerbackinfo"
		$ = "?action=getcmd&hostid="
		$ = "%s?action=gotcmd&hostid="
		$ = "%s?hostid=%s&hostname=%s&hostip=%s&filename=%s&filestart=%u&filetext="

		//debugging strings
		$ = "\x00Method1 Fail!!!!!\x00"
		$ = "\x00Method3 Fail!!!!!\x00"
		$ = "\x00method currect:\x00"
		$ = /\x00\x00[\w\-]+ is Running!\x00\x00/
		$ = "\x00OtherTwo\x00"

	condition:
		any of them

}

private rule NetpassStrings : NetPass Variant {

        meta:
                description = "Identifiers for netpass variant"
                author = "Katie Kleemola"
                last_updated = "2014-05-29"

        strings:
		$exif1 = "Device Protect ApplicatioN" wide
		$exif2 = "beep.sys" wide //embedded exe name
		$exif3 = "BEEP Driver" wide //embedded exe description
		
		$string1 = "\x00NetPass Update\x00"
		$string2 = "\x00%s:DOWNLOAD\x00"
		$string3 = "\x00%s:UPDATE\x00"
		$string4 = "\x00%s:uNINSTALL\x00"

        condition:
                all of ($exif*) or any of ($string*)

}	

private rule NSFreeCode : NSFree Family 
{
    meta:
        description = "NSFree code features"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
    
    strings:
        // push vars then look for MZ
        $ = { 53 56 57 66 81 38 4D 5A }
        // nops then look for PE\0\0
        $ = { 90 90 90 90 81 3F 50 45 00 00 }
    
    condition:
        all of them
}

private rule NSFreeStrings : NSFree Family
{
    meta:
        description = "NSFree Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    strings:
        $ = "\\MicNS\\" nocase
        $ = "NSFreeDll" wide ascii
        // xor 0x58 dos stub
        $ = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 78 3b 39 36 36 37 }
        
    condition:
       any of them
}

private rule OlyxCode : Olyx Family 
{
    meta:
        description = "Olyx code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $six = { C7 40 04 36 36 36 36 C7 40 08 36 36 36 36 }
        $slash = { C7 40 04 5C 5C 5C 5C C7 40 08 5C 5C 5C 5C }
        
    condition:
        any of them
}

private rule OlyxStrings : Olyx Family
{
    meta:
        description = "Olyx Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "/Applications/Automator.app/Contents/MacOS/DockLight"
       
    condition:
        any of them
}
private rule PlugXBootLDRCode : PlugX Family 
{
    meta:
        description = "PlugX boot.ldr code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-12"
        
    strings:
        //$callpop = { E8 00 00 00 00 58 }
        // Compares [eax+n] to GetProcAdd, one character at a time. This goes up to GetP:
        $GetProcAdd = { 80 38 47 75 36 80 78 01 65 75 30 80 78 02 74 75 2A 80 78 03 50 }
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_LoadLibraryA = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 4C 6F 61 64 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 4C 69 62 72 }
        $L4_VirtualAlloc = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 56 69 72 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 75 61 6C 41 }
        $L4_VirtualFree = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 56 69 72 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 75 61 6C 46 }
        $L4_ExitThread = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 45 78 69 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 54 68 72 65 }
        $L4_ntdll = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 6E 74 64 6C 66 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) C6 00 }
        $L4_RtlDecompressBuffer = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 52 74 6C 44 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 65 63 6F 6D }
        $L4_memcpy = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 6D 65 6D 63 66 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 70 79 }
        
    condition:
        /*($callpop at 0) or*/ $GetProcAdd or (all of ($L4_*))
}

private rule PlugXStrings : PlugX Family
{
    meta:
        description = "PlugX Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-12"
        
    strings:
        $BootLDR = "boot.ldr" wide ascii
        $Dwork = "d:\\work" nocase
        $Plug25 = "plug2.5"
        $Plug30 = "Plug3.0"
        $Shell6 = "Shell6"
      
    condition:
        $BootLDR or ($Dwork and ($Plug25 or $Plug30 or $Shell6))
}

private rule PubSabCode : PubSab Family 
{
    meta:
        description = "PubSab code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $decrypt = { 6B 45 E4 37 89 CA 29 C2 89 55 E4 }
        
    condition:
        any of them
}

private rule PubSabStrings : PubSab Family
{
    meta:
        description = "PubSab Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "_deamon_init"
        $ = "com.apple.PubSabAgent"
        $ = "/tmp/screen.jpeg"
       
    condition:
        any of them
}
private rule QuarianCode : Quarian Family 
{
    meta:
        description = "Quarian code features"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
    
    strings:
        // decrypt in intelnat.sys
        $ = { C1 E? 04 8B ?? F? C1 E? 05 33 C? }
        // decrypt in mswsocket.dll
        $ = { C1 EF 05 C1 E3 04 33 FB }
        $ = { 33 D8 81 EE 47 86 C8 61 }
        // loop in msupdate.dll
        $ = { FF 45 E8 81 45 EC CC 00 00 00 E9 95 FE FF FF }
    
    condition:
        any of them
}

private rule QuarianStrings : Quarian Family
{
    meta:
        description = "Quarian Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    strings:
        $ = "s061779s061750"
        $ = "[OnUpLoadFile]"
        $ = "[OnDownLoadFile]"
        $ = "[FileTransfer]"
        $ = "---- Not connect the Manager, so start UnInstall ----"
        $ = "------- Enter CompressDownLoadDir ---------"
        $ = "------- Enter DownLoadDirectory ---------"
        $ = "[HandleAdditionalData]"
        $ = "[mswsocket.dll]"
        $ = "msupdate.dll........Enter ThreadCmd!"
        $ = "ok1-1"
        $ = "msupdate_tmp.dll"
        $ = "replace Rpcss.dll successfully!"
        $ = "f:\\loadhiddendriver-mdl\\objfre_win7_x86\\i386\\intelnat.pdb"
        $ = "\\drivercashe\\" wide ascii
        $ = "\\microsoft\\windwos\\" wide ascii
        $ = "\\DosDevices\\LOADHIDDENDRIVER" wide ascii
        $ = "\\Device\\LOADHIDDENDRIVER" wide ascii
        $ = "Global\\state_maping" wide ascii
        $ = "E:\\Code\\2.0\\2.0_multi-port\\2.0\\ServerInstall_New-2010-0913_sp3\\msupdataDll\\Release\\msupdate_tmp.pdb"
        $ = "Global\\unInstall_event_1554_Ower" wide ascii
        
    condition:
       any of them
}
private rule RegSubDatCode : RegSubDat Family 
{
    meta:
        description = "RegSubDat code features"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop
        $ = { 80 34 3? 99 40 (3D FB 65 00 00 | 3B C6) 7? F? }
        // push then pop values
        $ = { 68 FF FF 7F 00 5? }
        $ = { 68 FF 7F 00 00 5? }
    
    condition:
        all of them
}

private rule RegSubDatStrings : RegSubDat Family
{
    meta:
        description = "RegSubDat Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    strings:
        $avg1 = "Button"
        $avg2 = "Allow"
        $avg3 = "Identity Protection"
        $avg4 = "Allow for all"
        $avg5 = "AVG Firewall Asks For Confirmation"
        $mutex = "0x1A7B4C9F"
        
    condition:
       all of ($avg*) or $mutex
}

private rule RSharedStrings : Surtr Family {
	meta:
		description = "identifiers for remote and gmremote"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = "nView_DiskLoydb" wide
		$ = "nView_KeyLoydb" wide
		$ = "nView_skins" wide
		$ = "UsbLoydb" wide
		$ = "%sBurn%s" wide
		$ = "soul" wide

	condition:
		any of them

}


private rule RemoteStrings : Remote Variant Surtr Family {
	meta:
		description = "indicators for remote.dll - surtr stage 2"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = "\x00Remote.dll\x00"
		$ = "\x00CGm_PlugBase::"
		$ = "\x00ServiceMain\x00_K_H_K_UH\x00"
		$ = "\x00_Remote_\x00" wide
	condition:
		any of them
}

private rule GmRemoteStrings : GmRemote Variant Family Surtr {
	meta:
		description = "identifiers for gmremote: surtr stage 2"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = "\x00x86_GmRemote.dll\x00"
		$ = "\x00D:\\Project\\GTProject\\Public\\List\\ListManager.cpp\x00"
		$ = "\x00GmShutPoint\x00"
		$ = "\x00GmRecvPoint\x00"
		$ = "\x00GmInitPoint\x00"
		$ = "\x00GmVerPoint\x00"
		$ = "\x00GmNumPoint\x00"
		$ = "_Gt_Remote_" wide
		$ = "%sBurn\\workdll.tmp" wide
	
	condition:
		any of them

}

/*
 * Check if File has shared identifiers among Surtr Stage 2's
 * Then look for unique identifiers to each variant
*/

rule GmRemote : Family Surtr Variant GmRemote {
	meta:
		description = "identifier for gmremote"
		author = "Katie Kleemola"
		last_updated = "07-25-2014"
	
	condition:
		RSharedStrings and GmRemoteStrings
}

private rule RookieCode : Rookie Family 
{
    meta:
        description = "Rookie code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        // hidden AutoConfigURL
        $ = { C6 ?? ?? ?? 41 C6 ?? ?? ?? 75 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 43 C6 ?? ?? ?? 6F C6 ?? ?? ?? 6E C6 ?? ?? ?? 66 }
        // hidden ProxyEnable
        $ = { C6 ?? ?? ?? 50 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 78 C6 ?? ?? ?? 79 C6 ?? ?? ?? 45 C6 ?? ?? ?? 6E C6 ?? ?? ?? 61 }
        // xor on rand value?
        $ = { 8B 1D 10 A1 40 00 [18] FF D3 8A 16 32 D0 88 16 }

    condition:
        any of them
}

private rule RookieStrings : Rookie Family
{
    meta:
        description = "Rookie Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "RookIE/1.0"
        
    condition:
       any of them
}
private rule RooterCode : Rooter Family 
{
    meta:
        description = "Rooter code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // xor 0x30 decryption
        $ = { 80 B0 ?? ?? ?? ?? 30 40 3D 00 50 00 00 7C F1 }
    
    condition:
        any of them
}

private rule RooterStrings : Rooter Family
{
    meta:
        description = "Rooter Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $group1 = "seed\x00"
        $group2 = "prot\x00"
        $group3 = "ownin\x00"
        $group4 = "feed0\x00"
        $group5 = "nown\x00"

    condition:
       3 of ($group*)
}

private rule SafeNetCode : SafeNet Family 
{
    meta:
        description = "SafeNet code features"
        author = "Seth Hardy"
        last_modified = "2014-07-16"
        
    strings:
        // add edi, 14h; cmp edi, 50D0F8h
        $ = { 83 C7 14 81 FF F8 D0 40 00 }
    condition:
        any of them
}

private rule SafeNetStrings : SafeNet Family
{
    meta:
        description = "Strings used by SafeNet"
        author = "Seth Hardy"
        last_modified = "2014-07-16"
        
    strings:
        $ = "6dNfg8Upn5fBzGgj8licQHblQvLnUY19z5zcNKNFdsDhUzuI8otEsBODrzFCqCKr"
        $ = "/safe/record.php"
        $ = "_Rm.bat" wide ascii
        $ = "try\x0d\x0a\x09\x09\x09\x09  del %s" wide ascii
        $ = "Ext.org" wide ascii
        
    condition:
        any of them

}

private rule ScarhiknCode : Scarhikn Family 
{
    meta:
        description = "Scarhikn code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $ = { 8B 06 8A 8B ?? ?? ?? ?? 30 0C 38 03 C7 55 43 E8 ?? ?? ?? ?? 3B D8 59 72 E7 }
        $ = { 8B 02 8A 8D ?? ?? ?? ?? 30 0C 30 03 C6 8B FB 83 C9 FF 33 C0 45 F2 AE F7 D1 49 3B E9 72 E2 }
    
    condition:
        any of them
}

private rule ScarhiknStrings : Scarhikn Family
{
    meta:
        description = "Scarhikn Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "9887___skej3sd"
        $ = "haha123"
        
    condition:
       any of them
}

rule Scieron
{
    meta:
        author = "Symantec Security Response"
        ref = "http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012"
        date = "22.01.15"

    strings:
        // .text:10002069 66 83 F8 2C                       cmp     ax, ','
        // .text:1000206D 74 0C                             jz      short loc_1000207B
        // .text:1000206F 66 83 F8 3B                       cmp     ax, ';'
        // .text:10002073 74 06                             jz      short loc_1000207B
        // .text:10002075 66 83 F8 7C                       cmp     ax, '|'
        // .text:10002079 75 05                             jnz     short loc_10002080
        $code1 = {66 83 F? 2C 74 0C 66 83 F? 3B 74 06 66 83 F? 7C 75 05}
        
        // .text:10001D83 83 F8 09                          cmp     eax, 9          ; switch 10 cases
        // .text:10001D86 0F 87 DB 00 00 00                 ja      loc_10001E67    ; jumptable 10001D8C default case
        // .text:10001D8C FF 24 85 55 1F 00+                jmp     ds:off_10001F55[eax*4] ; switch jump
        $code2 = {83 F? 09 0F 87 ?? 0? 00 00 FF 24}
        
        $str1  = "IP_PADDING_DATA" wide ascii
        $str2  = "PORT_NUM" wide ascii
        
    condition:
        all of them
}

rule TROJAN_Notepad {
    meta:
        Author = "RSA_IR"
        Date     = "4Jun13"
        File     = "notepad.exe v 1.1"
        MD5      = "106E63DBDA3A76BEEB53A8BBD8F98927"
    strings:
        $s1 = "75BAA77C842BE168B0F66C42C7885997"
        $s2 = "B523F63566F407F3834BCC54AAA32524"
    condition:
        $s1 or $s2
}
rule Trojan_Derusbi {
    meta:
        Author = "RSA_IR"
        Date     = "4Sept13"
        File     = "derusbi_variants v 1.3"
        MD5      = " c0d4c5b669cc5b51862db37e972d31ec "

    strings:
        $b1 = {8b 15 ?? ?? ?? ?? 8b ce d3 ea 83 c6 ?? 30 90 ?? ?? ?? ?? 40 3b 05 ?? ?? ?? ?? 72 ??}
        $b2 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E F7 5D 88 2E 0C A2 88 2E 4B 5D 88 2E F3 5D 88 2E}
        $b3 = {4E E6 40 BB}
        $b4 = {B1 19 BF 44}
        $b5 = {6A F5 44 3D ?? ?? 00 00 27 AF D4 3D 69 F5 44 3D 6E F5 44 3D 95 0A 44 3D D2 F5 44 3D 6A F5 44 3D}
        $b6 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E}
        $b7 = {D6 D5 A4 A3 ?? ?? 00 00 9B 8F 34 A3 D5 D5 A4 A3 D2 D5 A4 A3 29 2A A4 A3}
        $b8 = {C3 76 33 9F ?? ?? 00 00 8E 2C A3 9F C0 76 33 9F C7 76 33 9F 3C 89 33 9F}

    condition:
        2 of ($b1, $b2, $b3, $b4) and 1 of ($b5, $b6, $b7, $b8)
}

private rule SurtrCode : Surtr Family {
	meta: 
		author = "Katie Kleemola"
		description = "Code features for Surtr Stage1"
		last_updated = "2014-07-16"
	
	strings:
		//decrypt config
		$ = { 8A ?? ?? 84 ?? ?? 74 ?? 3C 01 74 ?? 34 01 88 41 3B ?? 72 ?? }
		//if Burn folder name is not in strings
		$ = { C6 [3] 42 C6 [3] 75 C6 [3] 72 C6 [3] 6E C6 [3] 5C }
		//mov char in _Fire
		$ = { C6 [3] 5F C6 [3] 46 C6 [3] 69 C6 [3] 72 C6 [3] 65 C6 [3] 2E C6 [3] 64 }

	condition:
		any of them

}

private rule SurtrStrings : Surtr Family {	
	meta: 
		author = "Katie Kleemola"
		description = "Strings for Surtr"
		last_updated = "2014-07-16"

	strings:
		$ = "\x00soul\x00"
		$ = "\x00InstallDll.dll\x00"
		$ = "\x00_One.dll\x00"
		$ = "_Fra.dll"
		$ = "CrtRunTime.log"
		$ = "Prod.t"
		$ = "Proe.t"
		$ = "Burn\\"
		$ = "LiveUpdata_Mem\\"

	condition:
		any of them

}
rule apt_c16_win_wateringhole 
{
  meta:
    author = "@dragonthreatlab "
    description = "Detects code from APT wateringhole"
  strings:
    $str1 = "function runmumaa()"
    $str2 = "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String("
    $str3 = "function MoSaklgEs7(k)"
  condition:
    any of ($str*)
}
rule apt_c16_win_swisyn 
{
  meta:
    author = "@dragonthreatlab"
    md5 = "a6a18c846e5179259eba9de238f67e41"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
  strings:
    $mz = {4D 5A}
    $str1 = "/ShowWU" ascii
    $str2 = "IsWow64Process"
    $str3 = "regsvr32 "
    $str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}
  condition:
    $mz at 0 and all of ($str*)
}
rule apt_c16_win32_dropper 
{
  meta:
    author = "@dragonthreatlab"
    md5 = "ad17eff26994df824be36db246c8fb6a"
    description = "APT malware used to drop PcClient RAT"
  strings:
    $mz = {4D 5A}
    $str1 = "clbcaiq.dll" ascii
    $str2 = "profapi_104" ascii
    $str3 = "/ShowWU" ascii
    $str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\" ascii
    $str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}
  condition:
    $mz at 0 and all of ($str*)
}
rule apt_c16_win64_dropper 
{
  meta:
    author = "@dragonthreatlab"
    md5 = "ad17eff26994df824be36db246c8fb6a"
    description = "APT malware used to drop PcClient RAT"
  strings:
    $mz = {4D 5A}
    $str1 = "clbcaiq.dll" ascii
    $str2 = "profapi_104" ascii
    $str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
    $str4 = {0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC}
  condition:
    $mz at 0 and all of ($str*)
}
rule apt_c16_win_disk_pcclient 
{
  meta:
    author = "@dragonthreatlab "
    md5 = "55f84d88d84c221437cd23cdbc541d2e"
    description = "Encoded version of pcclient found on disk"
  strings:
    $header = {51 5C 96 06 03 06 06 06 0A 06 06 06 FF FF 06 06 BE 06 06 06 06 06 06 06 46 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 EE 06 06 06 10 1F BC 10 06 BA 0D D1 25 BE 05 52 D1 25 5A 6E 6D 73 26 76 74 6F 67 74 65 71 26 63 65 70 70 6F 7A 26 64 69 26 74 79 70 26 6D 70 26 4A 4F 53 26 71 6F 6A 69 30 11 11 0C 2A 06 06 06 06 06 06 06 73 43 96 1B 37 24 00 4E 37 24 00 4E 37 24 00 4E BA 40 F6 4E 39 24 00 4E 5E 41 FA 4E 33 24 00 4E 5E 41 FC 4E 39 24 00 4E 37 24 FF 4E 0D 24 00 4E FA 31 A3 4E 40 24 00 4E DF 41 F9 4E 36 24 00 4E F6 2A FE 4E 38 24 00 4E DF 41 FC 4E 38 24 00 4E 54 6D 63 6E 37 24 00 4E 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 56 49 06 06 52 05 09 06 5D 87 8C 5A 06 06 06 06 06 06 06 06 E6 06 10 25 0B 05 08 06 06 1C 06 06 06 1A 06 06 06 06 06 06 E5 27 06 06 06 16 06 06 06 36 06 06 06 06 06 16 06 16 06 06 06 04 06 06 0A 06 06 06 06 06 06 06 0A 06 06 06 06 06 06 06 06 76 06 06 06 0A 06 06 06 06 06 06 04 06 06 06 06 06 16 06 06 16 06 06}
  condition:
    $header at 0
}
rule apt_c16_win_memory_pcclient 
{
  meta:
    author = "@dragonthreatlab "
    md5 = "ec532bbe9d0882d403473102e9724557"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
  strings:
    $str1 = "Kill You" ascii
    $str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
    $str3 = "%4.2f  KB" ascii
    $encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}  
  condition:
    all of them
}

private rule T5000Strings : T5000 Family
{
    meta:
        description = "T5000 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-26"
        
    strings:
        $ = "_tmpR.vbs"
        $ = "_tmpg.vbs"
        $ = "Dtl.dat" wide ascii
        $ = "3C6FB3CA-69B1-454f-8B2F-BD157762810E"
        $ = "EED5CA6C-9958-4611-B7A7-1238F2E1B17E"
        $ = "8A8FF8AD-D1DE-4cef-B87C-82627677662E"
        $ = "43EE34A9-9063-4d2c-AACD-F5C62B849089"
        $ = "A8859547-C62D-4e8b-A82D-BE1479C684C9"
        $ = "A59CF429-D0DD-4207-88A1-04090680F714"
        $ = "utd_CE31" wide ascii
        $ = "f:\\Project\\T5000\\Src\\Target\\1 KjetDll.pdb"
        $ = "l:\\MyProject\\Vc 7.1\\T5000\\T5000Ver1.28\\Target\\4 CaptureDLL.pdb"
        $ = "f:\\Project\\T5000\\Src\\Target\\4 CaptureDLL.pdb"
        $ = "E:\\VS2010\\xPlat2\\Release\\InstRes32.pdb"
        
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

private rule VidgrabCode : Vidgrab Family 
{
    meta:
        description = "Vidgrab code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
        // add eax, ecx; xor byte ptr [eax], ??h; inc ecx
        $xorloop = { 03 C1 80 30 (66 | 58) 41 }
        $junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }
        
    condition:
        all of them
}

private rule VidgrabStrings : Vidgrab Family
{
    meta:
        description = "Vidgrab Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $ = "IDI_ICON5" wide ascii
        $ = "starter.exe"
        $ = "wmifw.exe"
        $ = "Software\\rar"
        $ = "tmp092.tmp"
        $ = "temp1.exe"
        
    condition:
       3 of them
}


private rule WarpCode : Warp Family 
{
    meta:
        description = "Warp code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // character replacement
        $ = { 80 38 2B 75 03 C6 00 2D 80 38 2F 75 03 C6 00 5F }
    
    condition:
        any of them
}

private rule WarpStrings : Warp Family
{
    meta:
        description = "Warp Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $ = "/2011/n325423.shtml?"
        $ = "wyle"
        $ = "\\~ISUN32.EXE"

    condition:
       any of them
}

import "pe"

rule WaterBug_wipbot_2013_core_PDF 
{
    meta:
        description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 core PDF"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"
    
    strings:
        $PDF = "%PDF-"
        $a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/
        $b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/
    
    condition:
        ($PDF at 0) and #a > 150 and #b > 200
}

rule WaterBug_wipbot_2013_dll 
{
    meta:
        description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 Down.dll component"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"           
    strings:
        $string1 = "/%s?rank=%s"
        $string2 = "ModuleStart\x00ModuleStop\x00start"
        $string3 = "1156fd22-3443-4344-c4ffff"
        //read file... error..
        $string4 = "read\x20file\x2E\x2E\x2E\x20error\x00\x00"
    condition:
        2 of them
}

rule WaterBug_wipbot_2013_core 
{
    meta:
        description = "Symantec Waterbug Attack - Trojan.Wipbot core + core; garbage appended data (PDF Exploit leftovers) + wipbot dropper; fake AdobeRd32 Error"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"                   
    
    strings:
        $mz = "MZ"
        $code1 = { 89 47 0C C7 47 10 90 C2 04 00 C7 47 14 90 C2 10 00 C7 47 18 90 90 60 68 89 4F 1C C7 47 20 90 90 90 B8 89 4F 24 C7 47 28 90 FF D0 61 C7 47 2C 90 C2 04 00}
        $code2 = { 85 C0 75 25 8B 0B BF ?? ?? ?? ?? EB 17 69 D7 0D 66 19 00 8D BA 5F F3 6E 3C 89 FE C1 EE 10 89 F2 30 14 01 40 3B 43 04 72 E4}
        $code3 = {90 90 90 ?? B9 00 4D 5A 90 00 03 00 00 00 82 04} $code4 = {55 89 E5 5D C3 55 89 E5 83 EC 18 8B 45 08 85 C0}
    
    condition:
        $mz at 0 and (($code1 or $code2) or ($code3 and $code4))
}

rule WaterBug_turla_dropper 
{
    meta:
        description = "Symantec Waterbug Attack - Trojan Turla Dropper"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"

    strings:
        $a = {0F 31 14 31 20 31 3C 31 85 31 8C 31 A8 31 B1 31 D1 31 8B 32 91 32 B6 32 C4 32 6C 33 AC 33 10 34}
        $b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}

    condition:
        all of them
}

rule WaterBug_turla_dll 
{
    meta:
        description = "Symantec Waterbug Attack - Trojan Turla DLL"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"   

    strings:
        $a = /([A-Za-z0-9]{2,10}_){,2}Win32\.dll\x00/
   
    condition:
        pe.exports("ee") and $a
}
 
rule WaterBug_fa_malware 
{
    meta:
        description = "Symantec Waterbug Attack - FA malware variant"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"

    strings:
        $mz = "MZ"
        $string1 = "C:\\proj\\drivers\\fa _ 2009\\objfre\\i386\\atmarpd.pdb"
        $string2 = "d:\\proj\\cn\\fa64\\"
        $string3 = "sengoku_Win32.sys\x00"
        $string4 = "rk_ntsystem.c"
        $string5 = "\\uroboros\\"
        $string6 = "shell.{F21EDC09-85D3-4eb9-915F-1AFA2FF28153}"

    condition:
        ($mz at 0) and (any of ($string*))
}
 
rule WaterBug_sav_dropper
{
    meta:
        description = "Symantec Waterbug Attack - SAV Dropper"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"
    
    strings:
        $mz = "MZ"
        $a = /[a-z]{,10}_x64.sys\x00hMZ\x00/
    
    condition:
        ($mz at 0) and uint32(0x400) == 0x000000c3 and pe.number_of_sections == 6 and $a
}
 
rule WaterBug_sav 
{
    meta:
        description = "Symantec Waterbug Attack - SAV Malware"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"    
    
    strings:
        $mz = "MZ"
        $code1a = { 8B 75 18 31 34 81 40 3B C2 72 F5 33 F6 39 7D 14 76 1B 8A 04 0E 88 04 0F 6A 0F 33 D2 8B C7 5B F7 F3 85 D2 75 01 }
        $code1b = { 8B 45 F8 40 89 45 F8 8B 45 10 C1 E8 02 39 45 F8 73 17 8B 45 F8 8B 4D F4 8B 04 81 33 45 20 8B 4D F8 8B 55 F4 89 04 8A EB D7 83 65 F8 00 83 65 EC 00 EB 0E 8B 45 F8 40 89 45 F8 8B 45 EC 40 89 45 EC 8B 45 EC 3B 45 10 73 27 8B 45 F4 03 45 F8 8B 4D F4 03 4D EC 8A 09 88 08 8B 45 F8 33 D2 6A 0F 59 F7 F1 85 D2 75 07 }
        $code1c = { 8A 04 0F 88 04 0E 6A 0F 33 D2 8B C6 5B F7 F3 85 D2 75 01 47 8B 45 14 46 47 3B F8 72 E3 EB 04 C6 04 08 00 48 3B C6 73 F7 33 C0 C1 EE 02 74 0B 8B 55 18 31 14 81 40 3B C6 72 F5 }
        $code2 =  { 29 5D 0C 8B D1 C1 EA 05 2B CA 8B 55 F4 2B C3 3D 00 00 00 01 89 0F 8B 4D 10 8D 94 91 00 03 00 00 73 17 8B 7D F8 8B 4D 0C 0F B6 3F C1 E1 08 0B CF C1 E0 08 FF 45 F8 89 4D 0C 8B 0A 8B F8 C1 EF 0B}
    
    condition:
        ($mz at 0) and (($code1a or $code1b or $code1c) and $code2)
}
 
rule WaterBug_ComRat 
{
    meta:
        description = "Symantec Waterbug Attack - ComRat Trojan"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"    

    strings:
        $mz = "MZ"
        $b = { C6 45 ?? ?? }
        $c = { C6 85 ?? FE FF FF ?? }
        //$d = { FF A0 ?? 0? 00 00 }
        $e = { 89 A8 ?? 00 00 00 68 ?? 00 00 00 56 FF D7 8B }
        $f = { 00 00 48 89 ?? ?? 03 00 00 48 8B }
    
    condition:
        ($mz at 0) and ((#c > 200 and #b > 200 ) or /*(#d > 40) and*/ (#e > 15 or #f > 30))
}

private rule XtremeRATCode : XtremeRAT Family 
{
    meta:
        description = "XtremeRAT code features"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
    
    strings:
        // call; fstp st
        $ = { E8 ?? ?? ?? ?? DD D8 }
        // hiding string
        $ = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }
    
    condition:
        all of them
}

private rule XtremeRATStrings : XtremeRAT Family
{
    meta:
        description = "XtremeRAT Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    strings:
        $ = "dqsaazere"
        $ = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"
        
    condition:
       any of them
}

private rule WimmieShellcode : Wimmie Family 
{
    meta:
        description = "Wimmie code features"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
        
    strings:
        // decryption loop
        $ = { 49 30 24 39 83 F9 00 77 F7 8D 3D 4D 10 40 00 B9 0C 03 00 00 }
        $xordecrypt = {B9 B4 1D 00 00 [8] 49 30 24 39 83 F9 00 }
        
    condition:
        any of them
}

private rule WimmieStrings : Wimmie Family
{
    meta:
        description = "Strings used by Wimmie"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
        
    strings:
        $ = "\x00ScriptMan"
        $ = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" wide ascii
        $ = "ProbeScriptFint" wide ascii
        $ = "ProbeScriptKids"
        
    condition:
        any of them

}
rule YayihCode : Yayih Family 
{
    meta:
        description = "Yayih code features"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
    
    strings:
        //  encryption
        $ = { 80 04 08 7A 03 C1 8B 45 FC 80 34 08 19 03 C1 41 3B 0A 7C E9 }
    
    condition:
        any of them
}

rule YayihStrings : Yayih Family
{
    meta:
        description = "Yayih Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
        
    strings:
        $ = "/bbs/info.asp"
        $ = "\\msinfo.exe"
        $ = "%s\\%srcs.pdf"
        $ = "\\aumLib.ini"

    condition:
       any of them
}

