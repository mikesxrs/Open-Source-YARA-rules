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

rule APT3102 : Family
{
    meta:
        description = "3102"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        APT3102Code or APT3102Strings
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

rule APT9002 : Family
{
    meta:
        description = "9002"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        APT9002Code or APT9002Strings
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

rule Bangat : Family
{
    meta:
        description = "Bangat"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    condition:
        BangatCode or BangatStrings
}

rule dubseven_file_set
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for service files loading UP007"
    
    strings:
        $file1 = "\\Microsoft\\Internet Explorer\\conhost.exe"
        $file2 = "\\Microsoft\\Internet Explorer\\dll2.xor"
        $file3 = "\\Microsoft\\Internet Explorer\\HOOK.DLL"
        $file4 = "\\Microsoft\\Internet Explorer\\main.dll"
        $file5 = "\\Microsoft\\Internet Explorer\\nvsvc.exe"
        $file6 = "\\Microsoft\\Internet Explorer\\SBieDll.dll"
        $file7 = "\\Microsoft\\Internet Explorer\\mon"
        $file8 = "\\Microsoft\\Internet Explorer\\runas.exe"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        //Just a few of these as they differ
        3 of ($file*)
}

rule dubseven_dropper_registry_checks
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for registry keys checked for by the dropper"
    
    strings:
        $reg1 = "SOFTWARE\\360Safe\\Liveup"
        $reg2 = "Software\\360safe"
        $reg3 = "SOFTWARE\\kingsoft\\Antivirus"
        $reg4 = "SOFTWARE\\Avira\\Avira Destop"
        $reg5 = "SOFTWARE\\rising\\RAV"
        $reg6 = "SOFTWARE\\JiangMin"
        $reg7 = "SOFTWARE\\Micropoint\\Anti-Attack"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        all of ($reg*)
}

rule dubseven_dropper_dialog_remains
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants. How rude."
    
    strings:
        $dia1 = "fuckMessageBox 1.0" wide
        $dia2 = "Rundll 1.0" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        any of them
}
        

rule maindll_mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches on the maindll mutex"
        
    strings:
        $mutex = "h31415927tttt"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}


rule SLServer_dialog_remains
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants."
    
    strings:
        $slserver = "SLServer" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $slserver
}

rule SLServer_mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the mutex."
    
    strings:
        $mutex = "M&GX^DSF&DA@F"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}

rule SLServer_command_and_control
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the C2 server."
    
    strings:
        $c2 = "safetyssl.security-centers.com"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $c2
}

rule SLServer_campaign_code
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the related campaign code."
    
    strings:
        $campaign = "wthkdoc0106"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $campaign
}

rule SLServer_unknown_string
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for a unique string."
    
    strings:
        $string = "test-b7fa835a39"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $string
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
        //$1 = "Q\x00\x00\x00\x00W\x00\x00\x00\x00E\x00\x00\x00\x00R\x00\x00\x00\x00T\x00\x00\x00\x00Y\x00\x00\x00\x00"
        //$2 = "A\x00\x00\x00\x00S\x00\x00\x00\x00D\x00\x00\x00\x00F\x00\x00\x00\x00G\x00\x00\x00\x00H"
        //$3 = "Z\x00\x00\x00\x00X\x00\x00\x00\x00C\x00\x00\x00\x00V\x00\x00\x00\x00B\x00\x00\x00\x00N\x00\x00\x00\x00"
        $4 = "\\~Z8314.tmp"
        $5 = "hulee midimap" wide ascii
        
    condition:
       any of them
}

rule Boouset : Family
{
    meta:
        description = "Boouset"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        BoousetCode or BoousetStrings
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

rule Comfoo : Family
{
    meta:
        description = "Comfoo"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        ComfooCode or ComfooStrings
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

rule Cookies : Family
{
    meta:
        description = "Cookies"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        CookiesStrings
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

rule cxpid : Family
{
    meta:
        description = "cxpid"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    condition:
        cxpidCode or cxpidStrings
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

rule Enfal : Family
{
    meta:
        description = "Enfal"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        EnfalCode or EnfalStrings
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

rule Ezcob : Family
{
    meta:
        description = "Ezcob"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    condition:
        EzcobStrings
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

rule Favorite : Family
{
    meta:
        description = "Favorite"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    condition:
        FavoriteCode or FavoriteStrings
}

private rule IsRTF : RTF
{
    meta:
        description = "Identifier for RTF files"
        author = "Seth Hardy"
        last_modified = "2014-05-05"
        
    strings:
        $magic = /^\s*{\\rt/
    
    condition:
        $magic
}

private rule IsOLE : OLE
{
    meta:
        description = "Identifier for OLE files"
        author = "Seth Hardy"
        last_modified = "2014-05-06"
        
    strings:
        $magic = {d0 cf 11 e0 a1 b1 1a e1}
    
    condition:
        $magic at 0
}

private rule IsPE : PE 
{
	meta:
		description = "Identifier for PE files"
		last_modified = "2014-07-11"

	strings:
		$magic = { 5a 4d }

	condition:
		$magic at 0 and uint32(uint32(0x3C)) == 0x00004550
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

rule Glasses : Family
{
    meta:
        description = "Glasses family"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
   
    condition:
        GlassesCode or GlassesStrings
        
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

rule iexpl0re : Family
{
    meta:
        description = "iexpl0re family"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
   
    condition:
        iexpl0reCode or iexpl0reStrings
        
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

rule IMuler : Family
{
    meta:
        description = "IMuler"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    condition:
        IMulerCode or IMulerStrings
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

rule Insta11 : Family
{
    meta:
        description = "Insta11"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    condition:
        Insta11Code or Insta11Strings
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
        $trojanname = /WMILINK=.\*TrojanName=/
        $tmpfile = "d0908076343423d3456.tmp"
        $dirfile = "cmd /c dir /s /a C:\\\\ >'+tmpfolder+'\\\\C.tmp"
        $ipandmac = "objIP.DNSHostName+'_'+objIP.MACAddress.split(':').join('')+'_'+addinf+'@')"
        
    condition:
       any of them
}

rule LuckyCat : Family
{
    meta:
        description = "LuckyCat"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        LuckyCatCode or LuckyCatStrings
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

rule LURK0 : Family LURK0 {
	
	meta:
		description = "rule for lurk0"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"

	condition:
		LURK0Header and SharedStrings

}

rule CCTV0 : Family CCTV0 {

	meta:
		description = "rule for cctv0"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"

	condition:
		CCTV0Header and SharedStrings

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

rule MacControl : Family
{
    meta:
        description = "MacControl"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    condition:
        MacControlCode or MacControlStrings
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

rule Mirage : Family
{
    meta:
        description = "Mirage"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        MirageStrings
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

rule Mongal : Family
{
    meta:
        description = "Mongal"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    condition:
        MongalCode or MongalStrings
}

private rule MsAttackerStage2 : MsAttacker Family
{
	meta:
		description = "Identifying strings for MsAttacker stage 2"
		last_modified = "2015-03-12"
	strings:
		$ = "MiniJS.dll"
		$ = "%s \"rundll32.exe %s RealService %s\" /f"
		$ = "reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v \"Start Pages\" /f"
		$ = "3111431114311121270018000127001808012700180"
		$ = "Global\\MSAttacker %d"
	condition:
		any of them
}
private rule MsAttackerStage1 : MsAttacker Family
{
	meta:
		description = "Identifying strings for MsAttacker stage 1"
		last_modified = "2015-03-12"

	strings:
		$ = "http://122.10.117.152/download/ms/CryptBase.32.cab"
		$ = "http://122.10.117.152/download/ms/CryptBase.64.cab"
		$ = "http://122.10.117.152/download/ms/MiniJS.dll"
		$ = "MiniJS.dll"
		$ = "%s;new Downloader('%s', '%s').Fire();"
		$ = "rundll32.exe %s RealService %s"
	condition:
		any of them
}

rule MsAttacker : MsAttacker Family {
	condition:
		MsAttackerStage1 or MsAttackerStage2
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

rule Naikon : Family
{
    meta:
        description = "Naikon"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        NaikonCode or NaikonStrings
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

rule nAspyUpdate : Family
{
    meta:
        description = "nAspyUpdate"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    condition:
        nAspyUpdateCode or nAspyUpdateStrings
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


rule NetTraveler : Family {
	meta:
		description = "Nettravelr"
		author = "Katie Kleemola"
		last_updated = "2014-07-08"
	
	condition:
		NetTravExports or NetTravStrings or NetpassStrings

}

rule NetPass : Variant {
	meta:
		description = "netpass variant"
		author = "Katie Kleemola"
		last_updated = "2014-07-08"
	condition:
		NetpassStrings
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

rule NSFree : Family
{
    meta:
        description = "NSFree"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    condition:
        NSFreeCode or NSFreeStrings
}

/*

These string lists generated on the command line by:

Author:
file ~/samples/all/* | perl -ne 'if(/Author: (.*?), Template:/) { $x = $1; $x =~ s/\"/\\\"/g; while($x =~ /\\(\d{3})/) { $n = oct($1); $nn = sprintf("%02x",$n); $x =~ s/\\$1/\\x$nn/; chomp $x; } print "        \$ = \"\\x00$x\\x00\\x1e\"\n"; };' | sort | uniq

Title:
$ file ~/samples/all/* | perl -ne 'if(/Title: (.*?), Author:/) { $x = $1; $x =~ s/\"/\\\"/g; while($x =~ /\\(\d{3})/) { $n = oct($1); $nn = sprintf("%02x",$n); $x =~ s/\\$1/\\x$nn/; chomp $x; } print "        \$ = \"\\x00$x\\x00\\x1e\"\n"; };' | sort | uniq

Last Saved By:
$ file ~/samples/all/* | perl -ne 'if(/Last Saved By: (.*?), Revision/) { $x = $1; $x =~ s/\"/\\\"/g; while($x =~ /\\(\d{3})/) { $n = oct($1); $nn = sprintf("%02x",$n); $x =~ s/\\$1/\\x$nn/; chomp $x; }   print "        \$ = \"\\x00$x\\x00\\x1e\"\n"; };' | sort | uniq

*/


rule OLEAuthor : Author OLEMetadata
{
    meta:
        description = "Identifier for known OLE document authors"
        author = "Seth Hardy"
        last_modified = "2014-05-07"
        
    strings:
        $1 = "\x00111\x00\x1e"
        $2 = "\x0011\x00\x1e"
        $3 = "\x00123\x00\x1e"
        $4 = "\x002chu\x00\x1e"
        $5 = "\x007513A3DEA183474\x00\x1e"
        $6 = "\x00abc\x00\x1e"
        $7 = "\x00Administrator\x00\x1e"
        $8 = "\x00admin\x00\x1e"
        $9 = "\x00Aggarwal, Aakash\x00\x1e"
        $10 = "\x00beat\x00\x1e"
        $11 = "\x00Ben\x00\x1e"
        $12 = "\x00bf\x00\x1e"
        $13 = "\x00Booksway\x00\x1e"
        $14 = "\x00Bosh\x00\x1e"
        $15 = "\x00captain\x00\x1e"
        $16 = "\x00CC2\x00\x1e"
        $17 = "\x00cyano\x00\x1e"
        $18 = "\x00Dinesh\x00\x1e"
        $19 = "\x00Dolker\x00\x1e"
        $20 = "\x00Drokpa\x00\x1e"
        $21 = "\x00Findo\x00\x1e"
        $22 = "\x00FLORINE DATESSEN\x00\x1e"
        $23 = "\x00funghain\x00\x1e"
        $24 = "\x00HealthDeptt-01\x00\x1e"
        $25 = "\x00hy9901a\x00\x1e"
        $26 = "\x00IBM User\x00\x1e"
        $27 = "\x00IBM\x00\x1e"
        $28 = "\x00Igny\x00\x1e"
        $29 = "\x00IITK\x00\x1e"
        $30 = "\x00I. K\x00\x1e"
        $31 = "\x00Jamal Al-Masraf\x00\x1e"
        $32 = "\x00Joyce Havinga\x00\x1e"
        $33 = "\x00kalume\x00\x1e"
        $34 = "\x00Karma\x00\x1e"
        $35 = "\x00karmayeshi\x00\x1e"
        $36 = "\x00KChase\x00\x1e"
        $37 = "\x00ken\x00\x1e"
        $38 = "\x00khenrab\x00\x1e"
        $39 = "\x00Kunga Tashi\x00\x1e"
        $40 = "\x00Lenovo User\x00\x1e"
        $41 = "\x00Lenovo\x00\x1e"
        $42 = "\x00lenovo\x00\x1e"
        $43 = "\x00Lharisang\x00\x1e"
        $44 = "\x00Luitgard Hammerer\x00\x1e"
        $45 = "\x00MC SYSTEM\x00\x1e"
        $46 = "\x00mpzhang\x00\x1e"
        $47 = "\x00neuroking\x00\x1e"
        $48 = "\x00Ngawang Gelek\x00\x1e"
        $49 = "\x00niu2\x00\x1e"
        $50 = "\x00Owner\x00\x1e"
        $51 = "\x00pema tashi\x00\x1e"
        $52 = "\x00pepe\x00\x1e"
        $53 = "\x00perhat64\x00\x1e"
        $54 = "\x00Remote\x00\x1e"
        $55 = "\x00ResuR\x00\x1e"
        $56 = "\x00roy\x00\x1e"
        $57 = "\x00Samphel\x00\x1e"
        $58 = "\x00sard\x00\x1e"
        $59 = "\x00shirley\x00\x1e"
        $60 = "\x00shungqar\x00\x1e"
        $61 = "\x00Sofia Olsson\x00\x1e"
        $62 = "\x00Sonam Dolkar\x00\x1e"
        $63 = "\x00Son Huynh Hong\x00\x1e"
        $64 = "\x00system\x00\x1e"
        $65 = "\x00teguete\x00\x1e"
        $66 = "\x00tensangmo\x00\x1e"
        $67 = "\x00tenzin1959\x00\x1e"
        $68 = "\x00Tenzin\x00\x1e"
        $69 = "\x00Tran Duy Linh\x00\x1e"
        $70 = "\x00Traudl\x00\x1e"
        $71 = "\x00Tsedup\x00\x1e"
        $72 = "\x00Tsering Tamding\x00\x1e"
        $73 = "\x00unknown\x00\x1e"
        $74 = "\x00USER\x00\x1e"
        $75 = "\x00User\x00\x1e"
        $76 = "\x00user\x00\x1e"
        $77 = "\x00votoystein\x00\x1e"
        $78 = "\x00walkinnet\x00\x1e"
        $79 = "\x00World Uyghur Congress\x00\x1e"
        $80 = "\x00www\x00\x1e"
        //$81 = "\x00             \x00\x1e"
        //$82 = "\x00        \x00\x1e"
        //$83 = "\x00      \x00\x1e"
        //$84 = "\x00  \x00\x1e"
        $85 = "\x00\xf4_y\xb7\x80\x05\x9e\xbf\x00\x1e"
        $86 = "\x00xp\x00\x1e"
        $87 = "\x00YCanPDF\x00\x1e"
        $88 = "\x00y\x00\x1e"
        $89 = "\x00zsh\x00\x1e"

    condition:
        IsOLE and (any of them)
}


rule OLETitle : Title OLEMetadata
{
    meta:
        description = "Identifier for known OLE document titles"
        author = "Seth Hardy"
        last_modified = "2014-05-07"
        
    strings:
        $1 = "\x0001:00\x00\x1e"
        $2 = "\x00    23-Aprel  chushidin keyin saet bir yirim,Xitayning 3 neper paylaqchisi seriqbuya yezida oy arilap yurup paylaqchiliq qiliwatqanda bir oyge toplann\xcaghan bir gurup uyghur yashlarni korgen we ularning yenida pichaq we tam teshidighan eswablarni korup gum\x00\x1e"
        $3 = "\x0046-120603   fice W648\x00\x1e"
        $4 = "\x0054-120602   15s\xb7K\x0c]\xb7\x00\x1e"
        $5 = "\x005-Iyul Urumchi Qirghinchiliqi heqide qisqiche Dokilat \x00\x1e"
        $6 = "\x00April 20-21, 2013\x00\x1e"
        $7 = "\x00asdfasdfasdf\x00\x1e"
        $8 = "\x00Bamako, le 04 d\x00\x1e"
        $9 = "\x00Best\x00\x1e"
        $10 = "\x00Dear All,\x00\x1e"
        $11 = "\x00Dear President and Executive Members,\x00\x1e"
        $12 = "\x00Full list of self-immolations in Tibet\x00\x1e"
        $13 = "\x00Help stop the destruction of my home, Lhasa, Tibet\x00\x1e"
        $14 = "\x00HHDL'visit in European\x00\x1e"
        $15 = "\x00II) Overview & Analysis:\x00\x1e"
        $16 = "\x00Institute for Defence Studies and Analyses\x00\x1e"
        $17 = "\x00IPT  APPLICATION FORM\x00\x1e"
        $18 = "\x00Jharkhand supports Indian Parliamentary resolution on Tibet crisis\x00\x1e"
        $19 = "\x00Lieutenant General KENOSE BARRY PHILLIPE,\x00\x1e"
        $20 = "\x00OPERATIONAL MANUAL:\x00\x1e"
        $21 = "\x00PART 2 - Overview and Analysis\x00\x1e"
        $22 = "\x00PowerPoint Presentation\x00\x1e"
        $23 = "\x00Progress Chart: 15\x00\x1e"
        $24 = "\x00Progress Chart:\x00\x1e"
        $25 = "\x00Progress Chart\x00\x1e"
        $26 = "\x00RC\x00\x1e"
        $27 = "\x00(RESENDING)\x00\x1e"
        $28 = "\x00Talking Points EU-China Human Rights Dialogue June 2011\x00\x1e"
        $29 = "\x00TANC Community Center\x00\x1e"
        $30 = "\x00The Charg\x00\x1e"
        $31 = "\x00The following schedule of plans has been finalized for the purpose of holding the Second Special General Meeting of Tibetans being organized jointly by the Tibetan Parliament-in-Exile and the Kashag headed by the Kalon Tripa in accordance with the provis\x00\x1e"
        $32 = "\x00The Tibet Museum Project\x00\x1e"
        $33 = "\x00Tibetan Community in Switzerland & Liechtenstein, Binzstrasse 15, CH-8045 Zurich, Switzerland \x00\x1e"
        $34 = "\x00TSERING BHUTI\x00\x1e"
        $35 = "\x00Tsering Bhuti\x00\x1e"
        //$36 = "\x00 \x00\x1e"
        $37 = "\x00#\x00\x1e"
        $38 = "\x00\x8d\x00\x1e"
        $39 = "\x00\x8d\x9a\x06\xb7\x00\x1e"
        $40 = "\x00\xc8\xf8!\xb7\x00\x1e"
        $41 = "\x00Yes, I would like to raise this point: how many more young Tibetan lives are to be sacrificed in these awful self immolations before China is likely to change its Tibet policies in favour of Tibetan autonomy\x00\x1e"


    condition:
        IsOLE and (any of them)
}

rule OLELastSavedBy : LastSavedBy OLEMetadata
{
    meta:
        description = "Identifier for known OLE document Last Saved By field"
        author = "Seth Hardy"
        last_modified = "2014-05-07"
        
    strings:
        $1 = "\x00111\x00\x1e"
        $2 = "\x0011\x00\x1e"
        $3 = "\x00123\x00\x1e"
        $4 = "\x00Administrator\x00\x1e"
        $5 = "\x00Admin\x00\x1e"
        $6 = "\x00Alex\x00\x1e"
        $7 = "\x00Audit\x00\x1e"
        $8 = "\x00A\x00\x1e"
        $9 = "\x00beat\x00\x1e"
        $10 = "\x00Ben\x00\x1e"
        $11 = "\x00bf\x00\x1e"
        $12 = "\x00Booksway\x00\x1e"
        $13 = "\x00Bosh\x00\x1e"
        $14 = "\x00captain\x00\x1e"
        $15 = "\x00CL_nelson\x00\x1e"
        $16 = "\x00Core\x00\x1e"
        $17 = "\x00cyano\x00\x1e"
        $18 = "\x00dainzin\x00\x1e"
        $19 = "\x00Dolker\x00\x1e"
        $20 = "\x00Findo\x00\x1e"
        $21 = "\x00FLORINE DATESSEN\x00\x1e"
        $22 = "\x00funghain\x00\x1e"
        $23 = "\x00HP\x00\x1e"
        $24 = "\x00hy9901a\x00\x1e"
        $25 = "\x00IBM User\x00\x1e"
        $26 = "\x00IBM\x00\x1e"
        $27 = "\x00Igny\x00\x1e"
        $28 = "\x00I. K\x00\x1e"
        $29 = "\x00ITCO\x00\x1e"
        $30 = "\x00jds\x00\x1e"
        $31 = "\x00Joyce Havinga\x00\x1e"
        $32 = "\x00karmayeshi\x00\x1e"
        $33 = "\x00ken\x00\x1e"
        $34 = "\x00khenrab\x00\x1e"
        $35 = "\x00Kunga Tashi\x00\x1e"
        //$36 = "\x00lebrale\x00\x1e"
        $37 = "\x00Lenovo User\x00\x1e"
        $38 = "\x00Lenovo\x00\x1e"
        $39 = "\x00lenovo\x00\x1e"
        $40 = "\x00Lharisang\x00\x1e"
        $41 = "\x00Lhundup Damcho\x00\x1e"
        $42 = "\x00MC SYSTEM\x00\x1e"
        $43 = "\x00mm\x00\x1e"
        $44 = "\x00mpzhang\x00\x1e"
        $45 = "\x00neuroking\x00\x1e"
        $46 = "\x00niu2\x00\x1e"
        $47 = "\x00Normal.d\x00\x1e"
        $48 = "\x00Normal.w\x00\x1e"
        $49 = "\x00Normal\x00\x1e"
        $50 = "\x00one\x00\x1e"
        $51 = "\x00Owner\x00\x1e"
        $52 = "\x00pema tashi\x00\x1e"
        $53 = "\x00pepe\x00\x1e"
        $54 = "\x00PhiDiem\x00\x1e"
        $55 = "\x00ResuR\x00\x1e"
        $56 = "\x00roy\x00\x1e"
        $57 = "\x00Samphel\x00\x1e"
        $58 = "\x00system\x00\x1e"
        $59 = "\x00TCC Dhasa1\x00\x1e"
        $60 = "\x00tensangmo\x00\x1e"
        $61 = "\x00Tenzin\x00\x1e"
        $62 = "\x00test\x00\x1e"
        $63 = "\x00Tibet Ever\x00\x1e"
        $64 = "\x00Tran Duy Linh\x00\x1e"
        $65 = "\x00Traudl\x00\x1e"
        $66 = "\x00unknown\x00\x1e"
        $67 = "\x00User\x00\x1e"
        $68 = "\x00user\x00\x1e"
        $69 = "\x00USR\x00\x1e"
        $70 = "\x00walkinnet\x00\x1e"
        $71 = "\x00WIN7\x00\x1e"
        $72 = "\x00www\x00\x1e"
        //$73 = "\x00             \x00\x1e"
        //$74 = "\x00        \x00\x1e"
        //$75 = "\x00      \x00\x1e"
        //$76 = "\x00  \x00\x1e"
        $77 = "\x00y\x00\x1e"

    condition:
        IsOLE and (any of them)
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

rule Olyx : Family
{
    meta:
        description = "Olyx"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        OlyxCode or OlyxStrings
}

rule XYPayload : Payload
{
    meta:
        description = "Identifier for payloads using XXXXYYYY/YYYYXXXX markers"
        author = "Seth Hardy"
        last_modified = "2014-05-05"
        
    strings:
        $start_marker = "XXXXYYYY"
        $end_marker = "YYYYXXXX"
    
    condition:
        $start_marker and $end_marker
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
        /*($callpop at 0) or */ $GetProcAdd or (all of ($L4_*))
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

rule PlugX : Family
{
    meta:
        description = "PlugX"
        author = "Seth Hardy"
        last_modified = "2014-06-12"
        
    condition:
        PlugXBootLDRCode or PlugXStrings
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

rule PubSab : Family
{
    meta:
        description = "PubSab"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        PubSabCode or PubSabStrings
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

rule Quarian : Family
{
    meta:
        description = "Quarian"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    condition:
        QuarianCode or QuarianStrings
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

rule RegSubDat : Family
{
    meta:
        description = "RegSubDat"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    condition:
        RegSubDatCode or RegSubDatStrings
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

rule Remote : Family Surtr Variant Remote {
	meta:
		description = "identifier for remote"
		author = "Katie Kleemola"
		last_updated = "07-25-2014"
	
	condition:
		RSharedStrings and RemoteStrings
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

rule Rookie : Family
{
    meta:
        description = "Rookie"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        RookieCode or RookieStrings
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

rule Rooter : Family
{
    meta:
        description = "Rooter"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    condition:
        RooterCode or RooterStrings
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

rule SafeNet : Family
{
    meta:
        description = "SafeNet family"
        
    condition:
        SafeNetCode or SafeNetStrings
        
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

rule Scarhikn : Family
{
    meta:
        description = "Scarhikn"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        ScarhiknCode or ScarhiknStrings
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

rule Surtr : Family {
	meta:
		author = "Katie Kleemola"
		description = "Rule for Surtr Stage One"
		last_updated = "2014-07-16"

	condition:
		SurtrStrings or SurtrCode

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

rule T5000 : Family
{
    meta:
        description = "T5000"
        author = "Seth Hardy"
        last_modified = "2014-06-26"
        
    condition:
        T5000Strings
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

rule Vidgrab : Family
{
    meta:
        description = "Vidgrab"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        VidgrabCode or VidgrabStrings
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

rule Warp : Family
{
    meta:
        description = "Warp"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    condition:
        WarpCode or WarpStrings
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

rule Wimmie : Family
{
    meta:
        description = "Wimmie family"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
   
    condition:
        WimmieShellcode or WimmieStrings
        
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

rule XtremeRAT : Family
{
    meta:
        description = "XtremeRAT"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    condition:
        XtremeRATCode or XtremeRATStrings
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

rule Yayih : Family
{
    meta:
        description = "Yayih"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
        
    condition:
        YayihCode or YayihStrings
}