rule auriga : apt
{
    strings:
        $a = "%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x"
        $b = "auriga"
        $c = "McUpdate"
        $d = "download"
        $e = "upload"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule bouncer_dll : apt
{
    strings:
        $a = "select"
        $b = "%s: %s"
        $c = "sa:%s"
		$d = ";PWD="
		$e = "Computer Numbers: %d"
    condition:
        filesize < 350KB and (5 of ($a,$b,$c,$d,$e))
}

rule bouncer_exe : apt
{
    strings:
        $a = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg"
        $b = "dump"
        $c = "IDR_DATA%d"
    condition:
        filesize < 300KB and (3 of ($a,$b,$c))
}

rule bouncer2_exe : apt
{
    strings:
        $a = "asdfqwe123cxz"
        $b = "dump"
        $c = "loadlibrary kernel32 error %d"
    condition:
        filesize < 300KB and (3 of ($a,$b,$c))
}

rule calendar : apt
{
    strings:
        $a = "DownRun success"
        $b = "GoogleLogin auth="
        $c = "%s@gmail.com"
		$d = "log command"
		$e = "%s: %s"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule combos : apt
{
    strings:
        $a = "showthread.php?t="
        $b = "Getfile"
        $c = "Putfile"
		$d = "file://"
		$e = "https://%s"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule cookiebag : apt
{
    strings:
        $a = "?ID="
        $b = ".asp"
        $c = "clientkey"
		$d = "GetCommand"
		$e = "Set-Cookie:"
  	condition:
        filesize < 100KB and (5 of ($a,$b,$c,$d,$e))
}

rule dairy : apt
{
    strings:
        $a = "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c"
        $b = "Mozilla/4.0 (compatible; MSIE 7.0;)"
        $c = "dir %temp%"
		$d = "pklist"
		$e = "pkkill"
    condition:
        filesize < 100KB and (5 of ($a,$b,$c,$d,$e))
}

rule gdocupload : apt
{
    strings:
        $a = "CONOUT$"
        $b = "length=%d,time=%fsec,speed=%fk"
		$c = "%s%s%s"
		$d = "http://docs.google.com/?auth="
		$e = "x-fpp-command: 0"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule getmail : apt
{
    strings:
        $a = "Lu's Zany Message Store"
        $b = "IP"
		$c = "%s%i %s%i"
		$d = "-c key too long(MAX=16)"
		$e = "-f file name too long"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}


rule glooxmail : apt
{
    strings:
        $a = "This is gloox"
        $b = "Getfile Abrot!"
        $c = "glooxtest"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule goggles : apt
{
    strings:
        $a = "thequickbrownfxjmpsvalzydg"
        $b = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; %s.%s)"
    condition:
        filesize < 200KB and (2 of ($a,$b))
}

rule greencat : apt
{
    strings:
        $a = "computer name:"
        $b = "McUpdate"
        $c = "%s\\%d.bmp"
		$d = "version: %s v%d.%d build %d%s"
		$e = "Ca Incert"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule hacksfase : apt
{
    strings:
        $a = "!@#%$^#@!"
        $b = "Cann't create remote process!"
		$c = "tthacksfas@#$"
    condition:
        filesize < 300KB and (3 of ($a,$b,$c))
}

rule helauto : apt
{
    strings:
        $a = "D-o-w-n-l-o-a-d-f-i-l-e%s******%d@@@@@@%d"
        $b = "%*s %d %s"
		$c = "cmd /c net stop RasAuto"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule kurton : apt
{
    strings:
        $a = "HttpsUp||"
        $b = "!(*@)(!@PORT!(*@)(!@URL"
        $c = "root\\%s"
		$d = "HttpsFile||"
		$e = "Config service %s ok"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}


rule lightbolt : apt
{
    strings:
        $a = "bits.exe a all.jpg .\\ALL -hp%s"
        $b = "The %s store has been opened"
		$c = "Machine%d"
		$d = "Service%d"
		$e = "7z;ace;arj;bz2;cab;gz;jpeg;jpg;lha;lzh;mp3;rar;taz;tgz;z;zip"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule lightdart : apt
{
    strings:
        $a = "0123456789ABCDEF"
        $b = "ErrCode=%ld"
        $c = "ret.log"
        $d = "Microsoft Internet Explorer 6.0"
        $e = "szURL"
    condition:
        filesize < 200KB and (5 of ($a,$b,$c,$d,$e))
}

rule longrun : apt
{
    strings:
        $a = "%s\\%c%c%c%c%c%c%c"
        $b = "thequickbrownfxjmpsvalzydg"
    condition:
        filesize < 300KB and (2 of ($a,$b))
}

rule macromail : apt
{
    strings:
        $a = "get ok %d"
        $b = "put ok"
        $c = "GW-IP="
		$d = "messenger.hotmail.com"
		$e = "<d n=\"%s\">"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule manitsme : apt
{
    strings:
        $a = "rouji"
        $b = "Visual Studio"
        $c = "UglyGorilla"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c))
}

rule mapiget : apt
{
    strings:
        $a = "WNetCancelConnection2W"
        $b = "WNetAddConnection2W"
		$c = "%s -f:filename"
		$d = "CreateProcessWithLogonW"
		$e = "127.0.0.1"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule miniasp : apt
{
    strings:
        $a = ".asp?device_t=%s&key=%s&device_id=%s&cv=%s"
        $b = "result=%s"
        $c = "command=%s"
		$d = "wakeup="
    condition:
        filesize < 300KB and (4 of ($a,$b,$c,$d))
}

rule newsreels : apt
{
    strings:
        $a = "name=%s&userid=%04d&other=%c%s"
        $b = "thequickbrownfxjmpsvalzydg"
    condition:
        filesize < 300KB and (2 of ($a,$b))
}

rule seasalt : apt
{
    strings:
        $a = "%4d-%02d-%02d %02d:%02d:%02d"
        $b = "upfileok"
        $c = "upfileer"
		$d = "configserver"
    condition:
        filesize < 300KB and (4 of ($a,$b,$c,$d))
}

rule starsypound : apt
{
    strings:
        $a = "*(SY)# cmd"
        $b = "send = %d"
        $c = "cmd.exe"
		$d = "COMSPEC"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule sword : apt
{
    strings:
        $a = "Agent%ld"
        $b = "thequickbrownfxjmpsvalzydg"
        $c = "down:"
		$d = "exit"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule tabmsgsql : apt
{
    strings:
        $a = "accessip:%s"
        $b = "clientip:%s"
        $c = "Mozilla/4.0 (compatible; )"
		$d = "fromid:%s"
    condition:
        filesize < 300KB and (4 of ($a,$b,$c,$d))
}


rule tarsip : apt
{
    strings:
        $a = "%s/%s?%s"
        $b = "Mozilla/4.0 (compatible; MSIE 6.0;"
        $c = "Can not xo file!"
		$d = "cnnd"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule tarsip_eclipse : apt
{
    strings:
        $a = "Eclipse"
        $b = "PIGG"
        $c = "WAKPDT"
		$d = "show.asp?"
		$e = "flink?"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule warp : apt
{
    strings:
        $a = "Mozilla/4.0 (compatible; )"
        $b = "%u.%u.%u.%u"
        $c = "System info for machine"
		$d = "%2.2d-%2.2d-%4.4d %2.2d:%2.2d"
		$e = "https"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule webc2_adspace : apt
{
    strings:
        $a = "ntshrui"
        $b = "Microsoft(R) Windows(R) Operating System"
    condition:
        filesize < 100KB and (2 of ($a,$b))
}


rule webc2_ausov : apt
{
    strings:
        $a = "ntshrui"
        $b = "Microsoft(R) Windows(R) Operating System"
    condition:
        filesize < 300KB and (2 of ($a,$b))
}

rule webc2_bolid : apt
{
    strings:
        $a = ".htmlEEEEEEEEEEEEEEEEEEEEEEEEEEEEsleep:"
        $b = "downloadcopy:"
		$c = "geturl:"
		$d = "Q3JlYXRlUHJvY2Vzc0E="
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}


rule webc2_clover : apt
{
    strings:
        $a = "m i c r o s o f t"
        $b = "Default.asp"
		$c = "background="
		$d = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule webc2_cson : apt
{
    strings:
        $a = "/Default.aspx?INDEX="
        $b = "/Default.aspx?ID="
		$c = "Windows+NT+5.1"
		$d = "<!--"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule webc2_div : apt
{
    strings:
        $a = "Microsoft Internet Explorer"
        $b = "Hello from MFC!"
		$c = "3DC76854-C328-43D7-9E07-24BF894F8EF5"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_greencat : apt
{
    strings:
        $a = "shell"
        $b = "getf/putf FileName <N>"
		$c = "kill </p|/s> <pid|ServiceName>"
		$d = "list </p|/s|/d>"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule webc2_head : apt
{
    strings:
        $a = "<head>"
        $b = "</head>"
		$c = "connect %s"
		$d = "https://"
		$e = "Ready!"
    condition:
        filesize < 100KB and (5 of ($a,$b,$c,$d,$e))
}

rule webc2_kt3 : apt
{
    strings:
        $a = "*!Kt3+v| s:"
        $b = "*!Kt3+v| dne"
		$c = "*!Kt3+v|"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_qbp : apt
{
    strings:
        $a = "%t?%d-%d-%d="
        $b = "Hello@)!0"
		$c = "?id="
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_rave : apt
{
    strings:
        $a = "HTTP Mozilla/5.0(compatible+MSIE)"
        $b = "123!@#qweQWE"
		$c = "%s\\%s"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_table : apt
{
    strings:
        $a = "<![<endif>]--->"
        $b = "CreateThread() failed: %d"
		$c = "class="
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_ugx : apt
{
    strings:
        $a = "!@#dmc#@!"
        $b = "!@#tiuq#@!"
		$c = "!@#troppusnu#@!"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_y21k : apt
{
    strings:
        $a = "c2xlZXA="
        $b = "+Windows+NT+5.1"
		$c = "cXVpdA=="
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_yahoo : apt
{
    strings:
        $a = "<yahoo sb="
        $b = "<yahoo ex="
		$c = "letusgo"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}