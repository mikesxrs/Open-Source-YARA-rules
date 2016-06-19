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