rule MyWebSearchSample
{
    meta:
        Description = "Adware.MyWebSearch.vb"
        ThreatLevel = "5"

    strings:
		$ = "t8Setup1.pdb" ascii wide
		$ = "t8EIPlug.pdb" ascii wide
		$ = "t8EzSetp.pdb" ascii wide
		$ = "NPt8EISB.pdb" ascii wide
        $ = "Mindspark Interactive Network" ascii wide
        $ = "mindspark.com" ascii wide

    condition:
        any of them
}