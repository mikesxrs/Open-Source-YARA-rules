rule SearchSuiteSample
{
    meta:
        Description = "Adware.SearchSuite.vb"
        ThreatLevel = "5"

    strings:
        //$ = "SearchSuite" ascii wide
        $ = "searchcore.net" ascii wide
        $ = "searchnu.com" ascii wide
        $ = "searchqu.com" ascii wide
        $ = "searchsheet.com" ascii wide
        $ = "adoresearch.com" ascii wide
        $ = "newsearchtab.com" ascii wide
        $ = "searchsupreme.com" ascii wide
        $ = "mlsearch.com" ascii wide
        $ = "insertsearch.com" ascii wide
        $ = "gotsearch.com" ascii wide
        $ = "search.ask.com" ascii wide
        $ = "search-results.com" ascii wide
        $ = "default-search.net" ascii wide
        $ = "imesh web search" ascii wide

    condition:
        any of them
}