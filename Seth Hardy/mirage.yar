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