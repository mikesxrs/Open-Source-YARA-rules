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
        $trojanname = /WMILINK=.*TrojanName=/
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