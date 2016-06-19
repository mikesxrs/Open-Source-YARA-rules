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