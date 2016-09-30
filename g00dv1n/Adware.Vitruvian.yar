rule AdwareVitruvianSample
{
    meta:
        Description = "Adware.Vitruvian.vb"
        ThreatLevel = "5"

    strings:
		$ = "WordProser" ascii wide
		$ = "vitruvian" ascii wide
		$ = "gethighlightly.com" ascii wide
		$ = "betterbrainapp.com" ascii wide
		$ = "wordproser.com" ascii wide
		$ = "intellitermapp.com" ascii wide
		$ = "BetterBrainClientIE.pdb" ascii wide

    condition:
        any of them
}