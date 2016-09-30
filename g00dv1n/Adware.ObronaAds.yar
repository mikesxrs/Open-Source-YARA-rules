rule ObronaAdsSample
{
    meta:
        Description = "Adware.ObronaAds.vb"
        ThreatLevel = "5"

    strings:
        $i1 = "ObronaBlockAds" ascii wide
        $i2 = "Obrona Block Ads" ascii wide
        $i3 = "ObronaVPN" ascii wide
        $i4 = "OBRONA_PROXY" ascii wide
        $i5 = "SecurityAndShoppingAdvisor" ascii wide
        $i6 = "SASAService" ascii wide
        $i7 = "http://update.obrona.org" ascii wide
        $i8 = "Proxy-agent: SASA Proxy" ascii wide
        $i9 = "Proxy\\AdsInjectionContentProvider.cpp" ascii wide

        $ = "sendBrowsersHistoryKeywords" ascii wide
        $ = "startWatcher" ascii wide
        $ = "HelperApplication" ascii wide
        $ = "enableAds" ascii wide
        $ = "enableInjecting" ascii wide
        $ = "disableInjecting" ascii wide
        $ = "requestNewAdsUrl" ascii wide
        $ = "requestAdsIgnoredDomains" ascii wide
        $ = "startSendingSearchKeywords" ascii wide
        $ = "AdsService" ascii wide
        $ = "ServiceProxy.cpp" ascii wide
        $ = "HelperApplication.cpp" ascii wide
        $ = "Updater.cpp" ascii
        $ = "WebProxy.cpp" ascii wide

    condition:
        (any of ($i*)) or (3 of them)
}