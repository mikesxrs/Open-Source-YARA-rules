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
