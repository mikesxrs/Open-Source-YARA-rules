rule TriorisSample
{
    meta:
        Description = "Adware.Trioris.vb"
        ThreatLevel = "5"

    strings:
		$ = "instamarket.js" ascii wide
        $ = "instamarketoff.js" ascii wide
        $ = "trioris.net" ascii wide
        $ = "storegid.com" ascii wide
        $ = "screentoolkit.com" ascii wide
        $ = "Sergey Cherezov" ascii wide

    condition:
        any of them
}