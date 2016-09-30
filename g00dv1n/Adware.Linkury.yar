rule LinkuryASample
{
    meta:
        Description = "Adware.Linkury.A.vb"
        ThreatLevel = "5"

    strings:
        $ = "Smartbar" ascii wide
        $ = "Linkury" ascii wide
        $ = "ChromeUtils" ascii wide
        $ = "FirefoxUtils" ascii wide
        $ = "AddBundledSoftware" ascii wide
        $ = "UpdateToolbarState" ascii wide
        $ = "New Tab Search" ascii wide
        $ = "get_BrowserIsOpen" ascii wide
        $ = "get_BetterSearchResults" ascii wide
        $ = "get_AllYourBrowsers" ascii wide
        $ = "get_ChangeHomepageAndSearch" ascii wide
        $ = "get_BrowserSettingsProtectOk" ascii wide
        $ = "get_BrowserSettingsChange" ascii wide
        $ = "get_BrowserSettingsProtectChange" ascii wide
        $ = "get_BrowserSettingsProtectDescription" ascii wide
        $ = "get_BrowserSettingsProtectHeader" ascii wide
        $ = "get_BrowserSettingsProtectKeep" ascii wide

    condition:
        2 of them
}

rule LinkuryBSample
{
    meta:
        Description = "Adware.Linkury.B.vb"
        ThreatLevel = "5"

    strings:
        $ = "C:\\Cranberry\\bin\\CaraDelevigne\\Cara.pdb" ascii wide

    condition:
        any of them
}