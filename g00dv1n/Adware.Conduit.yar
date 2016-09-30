rule ConduitASample
{
    meta:
        Description = "Adware.Conduit.A.vb"
        ThreatLevel = "5"

    strings:
		$ = "GetSpeedBrowserInstalled" ascii wide
		$ = "SpeedBrowserAlreadyInstalled" ascii wide
		$ = "Injekt SVN - client" ascii wide

    condition:
        any of them
}

rule ConduitBSample
{
    meta:
        Description = "Adware.Conduit.B.vb"
        ThreatLevel = "5"

    strings:
		$ = "CAboutTabsInjector_" ascii wide
        $ = "AboutTabsDataUrlPublisher" ascii wide
        $ = "AboutTabsDataUrlConduit" ascii wide
        $ = "AboutTabsUsageUrl" ascii wide
        $ = "AboutTabsEnabledByUser" ascii wide
        $ = "AboutTabsEnabledByConduit" ascii wide
        $ = "AboutTabsEnabledByPublisher" ascii wide
        $ = "SearchInNewTabContent.xml" ascii wide
        $ = "CONDUIT_CHEVRON_MUTEX" ascii wide
        $ = "CConduitExternalForTBAPI" ascii wide
        $ = "EI_Toolbar_Update_Mutex" ascii wide

    condition:
        any of them
}