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