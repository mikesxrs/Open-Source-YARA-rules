rule AdwarePullUpdateSample
{
    meta:
        Description = "Adware.PullUpdate.vb"
        ThreatLevel = "5"

    strings:
        $ = "gettvwizard.com" ascii wide
        $ = "getsharethis.com" ascii wide
        $ = "thewebguard.com" ascii wide
        $ = "astro-arcade.com" ascii wide
        $ = "instashareonline.com" ascii wide
        $ = "safewebonline.com" ascii wide
        $ = "downloadmeteoroids.com" ascii wide
        $ = "moviemasterapp.com" ascii wide
        $ = "watchzombieinvasion.com" ascii wide
        $ = "freevideoconverterapp.com" ascii wide

       // $ = "TVWizard" ascii wide
        //$ = "TV Wizard" ascii wide
        $ = "AstroArcade" ascii wide
        $ = "WebGuard Deleter" ascii wide
        $ = "SmallIslandDevelopment" ascii wide

        $ = "AVFirefoxCookieReader" ascii wide
        $ = "AVChromeCookieReader" ascii wide
        $ = "AVInternetExplorerCookieReader" ascii wide
        $ = "AVBrowserCookieReader" ascii wide
        $ = "Data Protection Solutions" ascii wide


        $ = "VideoDimmer.exe" ascii wide
        $ = "VideoDimmerService.exe" ascii wide

        $ = "WebGuard.exe" ascii wide
        $ = "WebGuardService.exe" ascii wide

        $ = "HealthAlert.exe" ascii wide
        $ = "HealthAlertService.exe" ascii wide

        $ = "CrimeWatch.exe" ascii wide
        $ = "CrimeWatchService.exe" ascii wide

        $ = "SafeWeb.exe" ascii wide
        $ = "SafeWebService.exe" ascii wide

        $ = "Meteoroids.exe" ascii wide
        $ = "MeteoroidsService.exe" ascii wide

        $ = "Websteroids.exe" ascii wide
        $ = "WebsteroidsService.exe" ascii wide

        $ = "WebShield.exe" ascii wide
        $ = "WebShieldService.exe" ascii wide

        $ = "ZombieNews.exe" ascii wide
        $ = "ZombieNewsService.exe" ascii wide

        $ = "CelebrityAlertService.exe" ascii wide
        $ = "CelebrityAlert.exe" ascii wide

        $ = "MovieMaster.exe" ascii wide
        $ = "MovieMasterService.exe" ascii wide

        $ = "ZombieInvasionService.exe" ascii wide
        $ = "ZombieInvasion.exe" ascii wide

        $ = "BreakingNewsAlertService.exe" ascii wide
        $ = "BreakingNewsAlert.exe" ascii wide

    condition:
        any of them
}