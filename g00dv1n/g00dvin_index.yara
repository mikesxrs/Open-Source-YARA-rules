rule AdwareAdGazelleSample
{
	meta:
		Description  = "Adware.AdGazelle.vb"
		ThreatLevel  = "5"

	strings:

		$ = "D:\\popajar3" ascii wide
		$ = "squeakychocolate" ascii wide
		$ = "squeaky chocolate" ascii wide
		$ = "adxloader.dll" ascii wide
		$ = "adxloader.pdb" ascii wide
		$ = "adxloader64.dll" ascii wide
		$ = "adxloader64.pdb" ascii wide
		$ = "d:\\Products\\ADX.IE.8" ascii wide

	condition:
		any of them
}rule AdwareAdpeakSample
{
	meta:
		Description  = "Adware.Adpeak.vb"
		ThreatLevel  = "5"

	strings:

		$ = "dealcabby.dll" ascii wide
		$ = "getsavin.dll" ascii wide

	condition:
		any of them
}rule AdwarePricePeepSample
{
	meta:
		Description  = "Adware.PricePeep.vb"
		ThreatLevel  = "5"

	strings:

		$ = "BrandedUpdater" ascii wide
		$ = "default_browser" ascii wide
		$ = "LaunchDefaultBrowser" ascii wide
		$ = "LaunchBrowser" ascii wide

		$a1 = "InstallUtil.pdb" ascii wide
		$a2 = "C:\\managed\\root\\VTG_" ascii wide
		$a3 = "InstallUtil.pdb" ascii wide
		$a4 = "BrandedUpdater.pdb" ascii wide
		//$a5 = "PricePeep" ascii wide
		$a6 = "InstallUtil.cpp" ascii wide
		$a7 = "BrandedUpdater.cpp" ascii wide

	condition:
		(3 of them) or (any of ($a*))
}rule BetterSurfASample
{
    meta:
        Description = "Adware.BetterSurf.A.vb"
        ThreatLevel = "5"

    strings:
        $n1 = "Media Buzz" ascii wide
        $n2 = "MediaBuzz" ascii wide

        //$script1 = "document.getElementById('wsu_js" ascii wide
        //$script2 = "script.setAttribute('id','wsu_js" ascii wide

    condition:
       all of ($n*)
}rule AdwareBrowseFoxSample
{
	meta:
		Description  = "Adware.BrowseFox.vb"
		ThreatLevel  = "5"

	strings:

		$a2 = ".expextdll.dll" ascii wide
		$a3 = ".IEUpdate.pdb" ascii wide
		$a4 = ".Repmon.dll" ascii wide
		$a5 = ".BRT.Helper.exe" ascii wide
		$a6 = ".BrowserAdapter.pdb" ascii wide
		$a7 = ".expextdll.dll" ascii wide
		$a8 = ".browseradapter64.exe" ascii wide
		$a9 = ".purbrowse.exe" ascii wide
		$a10 = "BrowserFilter.exe" ascii wide
		$a11 = ".Bromon.dll" ascii wide
		$a12 = ".OfSvc.dll" ascii wide
		$a13 = ".GCUpdate.dll" ascii wide
		$a14 = ".BroStats.dll" ascii wide
		$a15 = ".BOAS.dll" ascii wide
		$a16 = ".BrowserAdapterS.dll" ascii wide
		$a17 = ".PurBrowse64.exe" ascii wide

		$b1 = "system32\\drivers\\%s.sys" ascii wide
		$b2 = "FilterApp" ascii wide

	condition:
		(any of ($a*)) or (all of ($b*))
}rule ConduitASample
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
}rule AdwareConvertAdSample
{
	meta:
		Description  = "Adware.ConvertAd.vb"
		ThreatLevel  = "5"

	strings:

		$ = "http://download-servers.com/SysInfo/adrouteservice/adrouter.php" ascii wide
		$ = "ConvertAd.html" ascii wide
		$ = "ConvertAd.exe" ascii wide

	condition:
		any of them
}rule AdwareCrossriderSampleA
{
	meta:
		Description  = "Adware.Crossrider.A.sm"
		ThreatLevel  = "5"

	strings:
		$ = "-bho.dll" ascii wide
		$ = "-bho64.dll" ascii wide
		$ = "-buttonutil64.dll" ascii wide
		$ = "-buttonutil.dll" ascii wide
		$ = "-BrowserEventSandBox" ascii wide
		$ = "CrossriderApp" ascii wide
		$ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe" ascii wide
		$ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe" ascii wide
		$ = "IEInject_Win32.dll" ascii wide
		$ = "bg_debug.js" ascii wide
		$ = "new_debug.js" ascii wide
		$ = "Browser Process id" ascii wide
		$ = "BHO Process id" ascii wide
		$ = "BhoRunningVersion" ascii wide
		$ = "-nova64.dll" ascii wide

		$str1 = "crossrider-buttonutil.pdb" ascii wide
		$str2 = "AVCCrossriderButtonHelper" ascii wide
		$str3 = "AVCCrossRiderLogger" ascii wide
		$str5 = "AddCrossRiderSearchProvider" ascii wide
		$str6 = "C:\\BUILD_AVZR2\\WhiteRabbit" ascii wide
		$str7 = "CrossriderBHO" ascii wide
		$str8 = "215AppVerifier" ascii wide
		$str9 = "Crossrider BHO Version" ascii wide
		$str10 = "brightcircleinvestments.com" ascii wide
		$str11 = "CrossriderNotification.pdb" ascii wide
		$str12 = "C:\\Users\\cross\\Desktop\\compilation_bot_area" ascii wide
	condition:
		(3 of them) or (any of ($str*))
}

rule AdwareCrossriderSampleB
{
	meta:
		Description  = "Adware.Crossrider.B.vb"
		ThreatLevel  = "5"

	strings:
		$ = "crossbrowse/updater/{{camp_id}}/{{version}}/{{secret}}/update.json" ascii wide
		$ = "Crossbrowse\\Crossbrowse\\Application\\crossbrowse.exe" ascii wide
		$ = "allnetserveline.com/crossbrowse" ascii wide
		$ = "C:\\workspace\\crossbrowse" ascii wide
		$ = "CrossriderBrowserInstaller.pdb" ascii wide

	condition:
		any of them
}
rule AdwareDealPlySample
{
	meta:
		Description  = "Adware.DealPly.vb"
		ThreatLevel  = "5"

	strings:

		$ = "dealply.prq" ascii wide

	condition:
		any of them
}rule AdwareDlhelperAdSample
{
	meta:
		Description  = "Adware.Dlhelper.vb"
		ThreatLevel  = "5"

	strings:

		$ = "trifonov@onegbsoft.ru" ascii wide
		$ = "bulovackiy@dontehnoservis.com.ua" ascii wide
		$ = "contacts@dayzgames.com" ascii wide
		$ = "admin@mayris.org" ascii wide

		$ = "Panel_OffersList" ascii wide

		$ = "support@dlhelper.com" ascii wide
		$ = "http://dlhelper.com" ascii wide

		$ = "http://sendme9.ru" ascii wide
		$ = "http://sendme3.ru" ascii wide
		$ = "http://trustfile3.ru" ascii wide
		$ = "http://trustfile9.ru" ascii wide
		$ = "http://downloaditeasy.ru" ascii wide

	condition:
		any of them
}rule AdwareDownloaderA
{
	meta:
		Description  = "Adware.Downloader.A.vb"
		ThreatLevel  = "5"

	strings:

		$ = "odiassi" ascii wide
		$ = "stavers" ascii wide
		$ = "trollimog" ascii wide
		$ = "diapause" ascii wide
		$ = "UserControl1" ascii wide
		$ = "listboxmod01" ascii wide

	condition:
		all of them
}rule AdwareELEXSampleA
{
	meta:
		Description  = "Adware.ELEX.A.vb"
		ThreatLevel  = "5"

	strings:

		$ = "www.freeappstools.com" ascii wide
		$ = "dl.elex.soft365.com" ascii wide
		$ = "E:\\Code\\FileSyn\\Bin" ascii wide
		$ = "E:\\Code_SVN\\FileSyn\\Bin" ascii wide

	condition:
		any of them
}


rule AdwareELEXSampleB
{
	meta:
		Description  = "Adware.ELEX.B.vb"
		ThreatLevel  = "5"

	strings:

		$pdb = "Release\\SFKEX.pdb" ascii wide
		$ = "21e223b3f0c97db3c281da1g7zccaefozzjcktmlma" ascii wide
		$ = "http://xa.xingcloud.com/v4/sof-everything" ascii wide
		$ = "http://www.mysearch123.com" ascii wide
		$ = "SFKEX.exe" ascii wide
		$ = "SFKEX.dll" ascii wide
		$ = "SFKURL" ascii wide

	condition:
		2 of them
}


rule AdwareELEXSampleCommon
{
	meta:
		Description  = "Adware.ELEX.vb"
		ThreatLevel  = "5"

	strings:

		$ = "\\Mozilla\\Firefox\\" ascii wide
		$ = "profiles.ini" ascii wide
		$ = "Profile0" ascii wide
		$ = "\\prefs.js" ascii wide
		$ = "\\Google\\Chrome\\User Data\\" ascii wide
		$ = "\\Secure Preferences" ascii wide
		$ = "Software\\Microsoft\\Internet Explorer\\Main" ascii wide
		$ = "Start Page" ascii wide
		$ = "chrome.exe" ascii wide
		$ = "iexplore.exe" ascii wide
		$ = "firefox.exe" ascii wide
		$ = "user_pref" ascii wide
		$ = "browser.startup.homepage" ascii wide
		$ = "startup_urls" ascii wide

	condition:
		all of them
}rule AdwareStormWatchSample
{
	meta:
		Description  = "Adware.StormWatch.vb"
		ThreatLevel  = "5"

	strings:

		$ = "localstormwatch.com" ascii wide
		$ = "StormWatch.pdb" ascii wide
		$ = "StormWatch.exe" ascii wide
		$ = "ActiveDeals" ascii wide

	condition:
		any of them
}rule AdwareGenieoSample
{
    meta:
        Description = "Adware.Genieo.vb"
        ThreatLevel = "5"

    strings:
		$h1 = "gentray.pdb" ascii wide
		$h2 = "genupdater.pdb" ascii wide
		$h3 = "www.genieo.com" ascii wide
        $h4 = "userfeedback-genieo.appspot.com" ascii wide
        $h5 = "Genieo Innovation LTD" ascii wide

        $str1 = "Software\\Genieo" ascii wide
        $str2 = "SOFTWARE\\Genieo" ascii wide

        $str5 = "genieo.exe" ascii wide
        $str6 = "genieutils.exe" ascii wide
        $str7 = "genupdater.exe" ascii wide

        $str8 = "__Genieo_" ascii wide
        $str9 = "GenieoUpdaterServiceCleaner" ascii wide
        $str10 = "GENIEO_TRAY_UI" ascii wide

    condition:
        any of them
}rule AdwareImaliSample
{
	meta:
		Description  = "Adware.Imali.vb"
		ThreatLevel  = "5"

	strings:

		$ = "www.freemediaplayer.tv" ascii wide

	condition:
		any of them
}rule AdwareInstallCoreSample
{
	meta:
		Description  = "Adware.InstallCore.vb"
		ThreatLevel  = "5"

	strings:

		$ = "www.mynicepicks.com" ascii wide
		$ = "www.ultimatepdfconverter.com" ascii wide
		$ = "www.coolpdfcreator.com" ascii wide
		$ = "cdnus.ironcdn.com" ascii wide
		$ = "esd.baixaki.com.br" ascii wide
		$ = "cdneu2.programmersupply.com" ascii wide

	condition:
		any of them
}rule LinkuryASample
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
}rule MyWebSearchSample
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
}rule NextLiveSample
{
    meta:
        Description = "Adware.NextLive.vb"
        ThreatLevel = "5"

    strings:

		$ = "nengine.pdb" ascii wide
		$ = "nengine.dll" ascii wide
		$ = "D:\\svn.thecodeway.com\\private\\nlive\\trunk" ascii wide

    condition:
        any of them
}rule ObronaAdsSample
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
}rule AdwareOpenCandySample
{
	meta:
		Description  = "Adware.OpenCandy.vb"
		ThreatLevel  = "5"

	strings:

		$ = "http://cdn.opencandy.com" ascii wide

	condition:
		any of them
}rule AdwareOutBrowseSample
{
	meta:
		Description  = "Adware.OutBrowse.vb"
		ThreatLevel  = "5"

	strings:

		$ = "cdn.install.playbryte.com" ascii wide
		$ = "download.2yourface.com" ascii wide
		$ = "www.default-page.com" ascii wide
		$ = "install2.optimum-installer.com" ascii wide
		$ = "downloadzone.org" ascii wide

	condition:
		any of them
}rule AdwarePullUpdateSample
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
}rule SearchProtectSample
{
    meta:
        Description = "Adware.SProtect.vb"
        ThreatLevel = "5"

    strings:
		$ = "Search Protect" ascii wide
		$ = "SearchProtect" ascii wide
		$ = "Search Protector" ascii wide
		$ = "SearchProtector" ascii wide
		$ = "ClientConnect" ascii wide
		$ = "SPVC32.dll" ascii wide
		$ = "SPVC32Loader.dll" ascii wide
		$ = "SPVC64.dll" ascii wide
		$ = "SPVC64Loader.dll" ascii wide
		$ = "SProtector" ascii wide
		$ = "AppendInit.dll" ascii wide
		$ = "{12DA0E6F-5543-440C-BAA2-28BF01070AFA}" ascii wide
		$pdb1 = "CltMngSvc.pdb" ascii wide
		$pdb2 = "SPtool.pdb" ascii wide
		$pdb3 = "SPtool64.pdb" ascii wide
		$pdb4 = "SPVC32.pdb" ascii wide
		$pdb5 = "SPVC64.pdb" ascii wide
		$pdb6 = "SPVC32Loader.pdb" ascii wide
		$pdb7 = "SPVC64Loader.pdb" ascii wide
		$pdb8 = "cltmng.pdb" ascii wide
		$pdb9 = "MiniStubUtils.pdb" ascii wide
		$pdb10 = "Search Protector" ascii wide
		$pdb11 = "%programfiles%\\Free Offers from" ascii wide
		$pdb12 = "TestSearchProtect" ascii wide
		$pdb13 = "ProtectService.pdb" ascii wide
		$pdb14 = "E:\\supsoft" ascii wide
		$pdb15 = "BrowerWatch.dll" ascii wide

    condition:
        (2 of them) or (any of ($pdb*))
}rule SearchSuiteSample
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
}rule AdwareSendoriSample
{
    meta:
        Description = "Adware.Sendori.vb"
        ThreatLevel = "5"

    strings:
		$ = "SendoriSvc.pdb" ascii wide
        $ = "SendoriTray.pdb" ascii wide
        $ = "sendori64f.sys" ascii wide
        $ = "sendori64r.sys" ascii wide
        $ = "sendori32.sys" ascii wide
        $ = "Sendori.dll" ascii wide
        $ = "SendoriProxy.dll" ascii wide
        $ = "SendoriUp.exe" ascii wide
        $ = "SendoriSvc.exe" ascii wide
        $ = "SendoriTray.exe" ascii wide
        $ = "SendoriControl.exe" ascii wide
        $ = "sendori-win-upgrader.exe" ascii wide
        $ = "\\\\.\\pipe\\Sendori" ascii wide
        $ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sendori" ascii wide
        $ = "SOFTWARE\\Sendori" ascii wide
        $ = "Sendori, Inc" ascii wide
        $ = "Sendori Service" ascii wide
        $ = "Service Sendori" ascii wide
        $ = "Application Sendori" ascii wide
        $ = "SendoriLSP" ascii wide
        $ = "Sendori Elevated Service Controller" ascii wide
        $ = "Sendori-Client" ascii wide
        $ = "SENDORI_UPGRADE_ASSISTANT" ascii wide

    condition:
        any of them
}rule SimplyTechSample
{
    meta:
        Description = "Adware.SimplyTech.vb"
        ThreatLevel = "5"

    strings:
        $ = "wtb_64.pdb" ascii wide
        $ = "wtb_64.DLL" ascii wide
        $ = "wtb.ToolbarInfo" ascii wide
        $ = "Surf Canyon" ascii wide
        $ = "surfcanyon" ascii wide

    condition:
        any of them
}rule SmartAppsSample
{
    meta:
        Description = "Adware.SmartApps.vb"
        ThreatLevel = "5"

    strings:

		$a1 = "Unicows.dll" ascii wide
		$a2 = "FrameworkBHO.DLL" ascii wide
		$a3 = "URLDownloadToFile" ascii wide
		$a4 = "getExtensionFileContents" ascii wide
		$a5 = "Toolbar" ascii wide
		$a6 = "GdiplusStartup" ascii wide

        $b1 = "getCookieW" ascii wide
        $b2 = "setCookieW" ascii wide
        $b3 = "InternetSetCookieW" ascii wide
        $b5 = "InternetGetCookieExW" ascii wide

    condition:
        (all of ($b*)) and (any of ($a*))
}rule AdwareSolimbdaSample
{
    meta:
        Description = "Adware.Solimbda.vb"
        ThreatLevel = "5"

    strings:
		$ = "http://api.downloadmr.com" ascii wide
		$ = "SuggestedApps" ascii wide

    condition:
        all of them
}rule TriorisSample
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
}rule AdwareVitruvianSample
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
}rule AdwareWajamSample
{
	meta:
		Description  = "Adware.Wajam.vb"
		ThreatLevel  = "5"

	strings:

		$ = "fastnfreedownload.com" ascii wide
		$ = "InternetEnhancer.exe" ascii wide
		$ = "InternetEnhancerService.exe" ascii wide
		$ = "WJManifest" ascii wide
		$ = "WaInterEnhance" ascii wide
		$ = "ping_wajam" ascii wide
		$ = "D:\\jenkins\\workspace" ascii wide
		$ = "WajamService" ascii wide
		$ = "AVCWJService" ascii wide
		$ = "Internet Enhancer Service" ascii wide

		$a1 = "WajamInternetEnhancerService.pdb" ascii wide
		$a4 = "WHttpServer.pdb" ascii wide
		$a2 = "Wajam. All right reserved" ascii wide
		$a3 = "Wajam.Proxy" ascii wide

	condition:
		(3 of them) or (any of ($a*))
}rule RootkitSampleDriverAgony
{
	meta:
		Description  = "Trojan.Agony.sm"
		ThreatLevel  = "5"

	strings:
		$  = "DosDevices\\agony" ascii wide
		$  = "Device\\agony" ascii wide
		$  = "VOLUME.INI" ascii wide
		$  = "ERVICES.EXE" ascii wide
		$  = "ervices.exe" ascii wide
		$  = "agony rootkit" ascii wide
		$  = "agony" ascii wide
		$  = "for exemple: agony -p process1.exe process2.exe" ascii wide
		$a = "i386\\agony.pdb" ascii wide

	condition:
		(3 of them) or $a
}

rule AdwareSampleWebTools
{
	meta:
		Description  = "Adware.WebTools.sm"
		ThreatLevel  = "5"

	strings:
		$ = "IEctrl.log" ascii wide
		$ = "agony" ascii wide
		$s1 = "Gates.pdb" ascii wide
		$s0 = "GatesInstall.pdb" ascii wide
		$s2 = "IECtrl.pdb" ascii wide
		$s3 = "svch0st.exe" ascii wide
		$s4 = "SESDKDummy.dll" ascii wide
		$s5 = "SESDKDummy64.dll" ascii wide

	condition:
		(3 of them) or (any of ($s*))
}rule AdwareWebWatcherSample
{
    meta:
        Description = "Adware.WebWatcher.vb"
        ThreatLevel = "5"

    strings:
		$ = "E:\\BuildSource\\7\\WindowsClient\\WindowsClient.Client.RC\\Binaries" ascii wide
		$ = "Release DlpHook\\mcapp.pdb" ascii wide
		$ = "Release DlpHook\\mcsc.pdb" ascii wide
		$ = "Release Sonar\\Shim64.pdb" ascii wide
		$ = "Release Sonar\\Shim.pdb" ascii wide

    condition:
        any of them
}rule AdwareiBryteSample
{
	meta:
		Description  = "Adware.iBryte.vb"
		ThreatLevel  = "5"

	strings:

		$ = "install.ibryte.com" ascii wide
		$ = "pn-installer28.com" ascii wide

	condition:
		any of them
}rule AdwareUCSKoreaSample
{
	meta:
		Description  = "Adware.uKor.sm"
		ThreatLevel  = "5"

	strings:
		$ = "_uninstall_Mutex" ascii wide
		$ = "_updater_Mutex" ascii wide
		$ = "_main_Mutex" ascii wide
		$ = "_install_Mutex" ascii wide
		$ = "main_agent" ascii wide
		$ = "updater_agent" ascii wide
		$ = "APP/bundle.php" ascii wide
		$ = "APP/update_ck.php?v1" ascii wide
		$ = "APP/bundle_stat.php?v1" ascii wide
		$ = "APP/stat.php?v1" ascii wide
		$ = "co.kr/mbk.php?v1" ascii wide
		$ = "co.kr/etc/yak_app.htm" ascii wide

		$hex1 = { 51 a1 ?? ?? ?? ?? 56 68 80 1f 40 00 50 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 33 d2 68 b8 0b 00 00 8d ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 85 c0 74 ?? 68 3f 00 0f 00 6a 00 6a 00 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 8b ?? ?? ?? ?? ?? 68 ff 01 0f 00 51 50 ff ?? ?? ?? ?? ?? 8b f0 85 f6 74 ?? 6a 00 6a 04 e8 ?? ?? ?? ?? 83 c4 08 68 c8 e8 41 00 ff ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 6a 01 e8 ?? ?? ?? ?? 83 c4 08 eb ?? 8b ?? ?? ?? 68 28 6e 42 00 6a 01 56 ff ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 5e 74 ?? 6a 00 ff ?? ?? ?? ?? ?? 8b d0 b8 01 00 00 00 e8 ?? ?? ?? ?? 83 c4 04 59 c2 08 00}

	condition:
		(2 of them) or (any of ($hex*))
}rule BladabindiASample
{
    meta:
        Description = "Backdoor.Bladabindi.A.vb"
        ThreatLevel = "5"

    strings:
        $ = "shutdown -r -t 00" ascii wide
        $ = "netsh firewall add allowedprogram" ascii wide
        $ = "netsh firewall delete allowedprogram" ascii wide
        $ = "cmd.exe /k ping 0 & del" ascii wide
        $ = "ReceiveBufferSize" ascii wide
        $ = "SendBufferSize" ascii wide
        $ = "restartcomputer" ascii wide
        $ = "NoWindowsUpdate" ascii wide
        $ = "winupdateoff" ascii wide
        $ = "DisableTaskMgr" ascii wide
        $ = "set cdaudio door closed" ascii wide
        $ = "set cdaudio door open" ascii wide
        $ = "VMDragDetectWndClass" ascii wide
        $ = "%dark%" ascii wide
        $ = "microwaveone.ddns.net" ascii wide

    condition:
        5 of them
}rule BackdoorDediprosA
{
        meta:
			Description  = "Backdoor.Dedipros.rc"
			ThreatLevel  = "5"

        strings:
            $ = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/advapi32.dll" ascii wide
			$ = "rundll32.exe %s, CodeMain lpServiceName" ascii wide
			$ = "C:\\Windows\\System32\\Rundlla.dll" ascii wide
			$ = "s%\\pmeT\\SWODNIW\\:C" ascii wide
			$ = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii wide
			$ = "\\keylog.dat" ascii wide
        condition:
            2 of them
}rule BackdoorWin32FynloskiASample
{
	meta:
		Description  = "Backdoor.Fynloski.sm"
		ThreatLevel  = "5"

	strings:
		$ = "#BOT#VisitUrl" ascii wide
		$ = "#BOT#OpenUrl" ascii wide
		$ = "#BOT#Ping" ascii wide
		$ = "BTRESULTPing|Res" ascii wide
		$ = "#BOT#RunPrompt" ascii wide
		$ = "BTRESULTClose" ascii wide
		$ = "#BOT#SvrUninstal" ascii wide
		$ = "#BOT#URLUpdate" ascii wide
		$ = "BTERRORUpdate" ascii wide
		$ = "BTRESULTUpdate" ascii wide
		$ = "#BOT#URLDownload" ascii wide
		$ = "BTRESULTOpen" ascii wide
		$ = "BTERRORDownload" ascii wide
		$ = "BTRESULTDownload" ascii wide
		$ = "BTRESULTMass" ascii wide
		$ = "BTRESULTHTTP" ascii wide
		$ = "BTERRORVisit" ascii wide
		$ = "BTRESULTSyn" ascii wide
		$ = "BTRESULTUDP" ascii wide
		$ = "Flood|UDP Flood task finished" ascii wide
		$ = "Flood|Syn task finished" ascii wide
		$ = "Flood|Http Flood task finished" ascii wide

	condition:
		3 of them
}rule BackdoorGenASample
{
    meta:
        Description = "Backdoor.Gen.A.vb"
        ThreatLevel = "5"

    strings:
        $ = "Form1" ascii wide
        $ = "Flamand" ascii wide
        $ = "Afildoe.Belver" ascii wide
        $ = "FromBase64String" ascii wide
        $ = "TeAdor.Properties.Resources" ascii wide

    condition:
        3 of them
}rule BackdoorLiudoor
{
meta:
        author = "RSA FirstWatch"
        date = "2015-07-23"
        Description = "Backdoor.Liudoor.sm"
        ThreatLevel  = "5"
        hash0 = "78b56bc3edbee3a425c96738760ee406"
        hash1 = "5aa0510f6f1b0e48f0303b9a4bfc641e"
        hash2 = "531d30c8ee27d62e6fbe855299d0e7de"
        hash3 = "2be2ac65fd97ccc97027184f0310f2f3"
		hash4 = "6093505c7f7ec25b1934d3657649ef07"
        type = "Win32 DLL"

strings:
        $string0 = "Succ" ascii wide
        $string1 = "Fail" ascii wide
        $string2 = "pass" ascii wide
        $string3 = "exit" ascii wide
        $string4 = "svchostdllserver.dll" ascii wide
        $string5 = "L$,PQR" ascii wide
        $string6 = "0/0B0H0Q0W0k0" ascii wide
        $string7 = "QSUVWh" ascii wide
        $string8 = "Ht Hu[" ascii wide
condition:
        all of them
}
rule MirageAPTBackdoorSample
{
        meta:
			Description  = "Backdoor.Mirage.sm"
			ThreatLevel  = "5"

        strings:
               $a1 = "welcome to the desert of the real" ascii wide
               $a2 = "Mirage" ascii wide
               $b = "Encoding: gzip" ascii wide
               $c = /\/[A-Za-z]*\?hl=en/
        condition:
               (($a1 or $a2) or $b) and $c
}rule TrojanWin32Vawtrak_BackDoor
{
	meta:
		Description  = "Backdoor.Win32.sm"
		ThreatLevel  = "5"

	strings:
		$ = "[VNC] New Client" ascii wide
		$ = "[VNC] Fail init BC" ascii wide
		$ = "[VNC] Fail addr proto BC" ascii wide
		$ = "[VNC] Fail connect BC" ascii wide
		$ = "[VNC] Fail init work:" ascii wide
		$ = "[VNC] Start Sever" ascii wide
		$ = "[VNC] Parse param error:" ascii wide
		$ = "[VNC] Fail create  process:" ascii wide
		$ = "[VNC] Fail inject to process:" ascii wide
		$ = "[Socks] New Client" ascii wide
		$ = "[Socks] Failt Init BC" ascii wide
		$ = "[Socks] Fail add proto BC" ascii wide
		$ = "[Socks] Failt connect BC" ascii wide
		$ = "[Socks] Fail parse param:" ascii wide
		$ = "[Pony] Fail Get Pass" ascii wide
		$ = "DL_EXEC Status [Pipe]" ascii wide
		$ = "DL_EXEC Status[Local]" ascii wide
		$ = "Start Socks addr:" ascii wide
		$ = "Start Socks Status[Pipe]" ascii wide
		$ = "Start Socks Status[Local]" ascii wide
		$ = "Start VNC addr: %s" ascii wide
		$ = "Start VNC Status[Pipe]: %u-%u-%u" ascii wide
		$ = "Start VNC Status[Local]: %u" ascii wide
		$ = "PID: %u [%0.2u:%0.2u:%0.2u]" ascii wide
		$ = "[BC] Cmd Ver Error" ascii wide
		$ = "[BC] Wait Ping error %u[%u]" ascii wide
		$ = "[BC] Fail Connect" ascii wide
		$ = "[BC] Fail send auth" ascii wide
		$ = "[BC] Fail read cmd" ascii wide
		$ = "[BC] cmd error: %u" ascii wide
		$ = "[BC] Cmd need disconnect" ascii wide
		$ = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" ascii wide
		
		$str_0 = "T:\\Develop\\EQ2\\bin\\tmp" ascii wide
		$str_1 = "T:\\Develop\\EQ2\\bin\\tmp\\client_32.pdb" ascii wide
		$str_2 = "T:\\Develop\\EQ2\\bin\\tmp\\client_64.pdb" ascii wide
		$str_3 = "client_64.dll" ascii wide   
		$str_4 = "client_32.dll" ascii wide

	condition:
		(5 of them) or (any of ($str_*))
}
rule BackdoorZegostSampleA
{
        meta:
			Description  = "Backdoor.Zegost.rc"
			ThreatLevel  = "5"

        strings:
            $a = "VIPBlackDDOS" ascii wide
			$b = "SynFlood" ascii wide
			$c = "ICMPFlood" ascii wide
			$d = "UDPFlood" ascii wide
			$e = "DNSFlood" ascii wide
			$f = "Game2Flood" ascii wide
			$g = "HTTPGetFlood" ascii wide
        condition:
            2 of them
}rule MalwareBitCoinMinerSample_A
{
	meta:
		Description  = "Malware.BitCoinMiner.sm"
		ThreatLevel  = "5"

	strings:
		$ = "Min3Win.exe" ascii wide
		$ = "bitcoin-miner.exe" ascii wide
		$ = "WINSXS32" ascii wide
		$ = "http://xhuehs.cantvenlinea.ru:1942" ascii wide
		$ = "bigbob0000001@gmail.com" ascii wide

	condition:
		3 of them
}rule TinyLoaderSample
{
	meta:
		Description  = "Malware.TinyLoader.vb"
		ThreatLevel  = "5"

	strings:

		$ = "B1 Tiny Loader/1.0" ascii wide

	condition:
		all of them
}rule PWSPasswordsToDBApp
{
	meta:
		Description  = "PWS.PassDB.sm"
		ThreatLevel  = "5"

	strings:

		$pdb0 = "PasswordsToDB.pdb" ascii wide
		$ipa0 = "82.146.47.116" ascii wide
		$ipa1 = "82.146.54.187" ascii wide

	condition:
		any of them
}rule PUPSystemOptimizerASample
{
	meta:
		Description  = "PUP.SystemOptimizer.vb"
		ThreatLevel  = "5"

	strings:

		$ = "http://bitest.softservers.net" ascii wide
		$ = "http://bi.softservers.net" ascii wide

	condition:
		any of them
}rule PUPSystweakSample
{
	meta:
		Description  = "PUP.Systweak.vb"
		ThreatLevel  = "5"

	strings:

		$ = "Systweak Software0" ascii wide
		$ = "pc-updater.com/miscservice/miscservice.asmx" ascii wide

	condition:
		any of them
}rule RansomCryptoApp_A
{
	meta:
		Description  = "Ransom.CryptoApp.sm"
		ThreatLevel  = "5"

	strings:

		$pdb0 = "CryptoApp.pdb" ascii wide
		$pdb1 = "KeepAlive.pdb" ascii wide
		$pdb2 = "SelfDestroy.pdb" ascii wide
		$pdb3 = "CoreDownloader.pdb" ascii wide

	condition:
		(3 of them) or (any of ($pdb*))
}

rule RansomCryptoWallApp_3
{
	meta:
		Description  = "Ransom.CryptoWall.sm"
		ThreatLevel  = "5"

	strings:

		$s0 = "spatopayforwin.com" ascii wide
		$s1 = "bythepaywayall.com" ascii wide
		$s2 = "lowallmoneypool.com" ascii wide
		$s3 = "transoptionpay.com" ascii wide
		$s4 = "HELP_DECRYPT" ascii wide nocase

		$s5 = "speralreaopio.com" ascii wide
        $s6 = "vremlreafpa.com" ascii wide
        $s7 = "wolfwallsreaetpay.com" ascii wide
        $s8 = "askhoreasption.com" ascii wide

	condition:
		any of ($s*)
}

rule RansomCBTLockerApp
{
	meta:
		Description  = "Ransom.CBTLocker.sm"
		ThreatLevel  = "5"

	strings:

		$s0 = "Your personal files are encrypted by CTB-Locker" ascii wide
		$s1 = "Your documents, photos, databases and other important files have been encrypted with strongest encryption and unique key,generated for this computer" ascii wide
		$s2 = "Private decryption key is stored on a secret Internet server and nobody can decrypt your files until you pay and obtain the private key." ascii wide
		$s3 = "If you see the main locker window, follow the instructions on the locker. Overwise, it's seems that you or your antivirus deleted the locker program" ascii wide

		$s6 = "keme132.DLL" ascii wide
		$s7 = "klospad.pdb" ascii wide

	condition:
		(any of ($s*)) or (3 of them)
}

rule RansomEncryptorRaaSApp
{
	meta:
		Description  = "Ransom.EncryptorRaaS.sm"
		ThreatLevel  = "5"

	strings:

		$s0 = "decryptoraveidf7.onion.to" ascii wide
		$s1 = "encryptor_raas_readme_liesmich.txt" ascii wide
		$s2 = "The files on your computer have been securely encrypted by Encryptor RaaS" ascii wide
		$s3 = "Die Dateien auf Ihrem Computer wurden von Encryptor RaaS sicher verschluesselt" ascii wide
		$s4 = "encryptor3awk6px.onion" ascii wide

	condition:
		any of ($s*)
}

rule RansomSampleTeslaCryptA
{
	meta:
		Description  = "Ransom.TeslaCrypt.sm"
		ThreatLevel  = "5"

	strings:
		$ = "HOWTO_RESTORE_FILES.TXT" ascii wide nocase
		$ = "HOWTO_RESTORE_FILES.bmp" ascii wide nocase
		$ = "HOWTO_RESTORE_FILES.HTML" ascii wide nocase
	condition:
		any of them
}

rule RansomSampleTeslaCryptB
{
	meta:
		Description  = "Ransom.TeslaCrypt.B.sm"
		ThreatLevel  = "5"

	strings:
		$ = "help_recover_instructions" ascii wide nocase
		$ = "help_recover_instructions.TXT" ascii wide nocase
		$ = "help_recover_instructions.png" ascii wide nocase
	condition:
		any of them
}

rule RansomSampleChimeraB
{
	meta:
		Description  = "Ransom.Win32.Chimera.sm"
		ThreatLevel  = "5"

	strings:
		$ = "YOUR_FILES_ARE_ENCRYPTED.HTML" ascii wide nocase
		$ = "Projects\\Ransom\\bin\\Release\\Core.pdb" ascii wide nocase
		$ = "BM-2cW44Yq9DWbHYnRSfzBLVxvE6WjadchNBt" ascii wide nocase
	condition:
		any of them
}

rule RansomSampleLeChiffre
{
	meta:
		Description  = "Ransom.Win32.LeChiffre.sm"
		ThreatLevel  = "5"

	strings:
		$ = "LeChiffre" ascii wide nocase
		$ = "decrypt.my.files@gmail.com" ascii wide nocase
		$ = "http://184.107.251.146/sipvoice.php?" ascii wide nocase
		$ = "_secret_code.txt" ascii wide nocase
		$ = "_How to decrypt LeChiffre files.html" ascii wide nocase
	condition:
		2 of them
}

rule RansomSampleHydraCrypt
{
	meta:
		Description  = "Ransom.Win32.HydraCrypt.sm"
		ThreatLevel  = "5"

	strings:
		$ = "README_DECRYPT_HYDRA_ID_" ascii wide nocase
		$ = "hydracrypt_ID_" ascii wide nocase
		$ = "HYDRACRYPT" ascii wide nocase
		$ = "ccc=hydra01_" ascii wide nocase
	condition:
		2 of them
}

rule RansomFilecoderA
{
	meta:
		Description  = "Ransom.FileCoder.A.vb"
		ThreatLevel  = "5"

	strings:
		$ = "Guji36" ascii wide
		$ = "Burnamedoxi" ascii wide
		$ = "S48H1G54JSPSODKMGdfH1FD5G8DSDPSDKMFSSJJPGMCNDHS2FH5" ascii wide
	condition:
		any of them
}

rule RansomSampleLockyCrypt
{
	meta:
		Description  = "Ransom.Win32.Locky.sm"
		ThreatLevel  = "5"

	strings:
		$s1 = ".locky" ascii wide nocase
		$ = "&encrypted=" ascii wide nocase
		$s2 = "_Locky_recover_instructions.txt" ascii wide nocase
		$s3 = "_Locky_recover_instructions.bmp" ascii wide nocase
		$ = "94.242.57.45" ascii wide nocase
		$ = "46.4.239.76" ascii wide nocase
		$s6 = "Software\\Locky" ascii wide nocase
		$ = "vssadmin.exe Delete Shadows" ascii wide nocase
		$ = "Locky" ascii wide nocase

		$o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } // address=0x4144a7
		$o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } // address=0x413863

	condition:
		(3 of them) or (any of ($s*)) or (all of ($o*))
}

import "pe"
rule RansomLocky
{
	meta:
		Description  = "Ransom.Locky.ab"
		ThreatLevel  = "5"
	strings:
		$mz = { 4d 5a }

		$inst1 = "_HELP_instructions.bmp" ascii wide
		$inst2 = "_HELP_instructions.html" ascii wide
		$inst3 = "_HELP_instructions.txt" ascii wide
		$inst4 = "_Locky_recover_instructions.bmp" ascii wide
		$inst5 = "_Locky_recover_instructions.txt" ascii wide
		$deleteShadows = "vssadmin.exe" ascii wide // universal Ransom detect :)

		$cyrptEP1 = {e8 95 23 ff ff 86 c8 86 ea e9 8d 23 ff ff 86 f4 e9 84 23 ff ff 86 c5} // EP paked locy
		$cyrptEP2 = {55 8b ec eb 68 eb 66 eb 64 6a 00 6a 00 6a 00 6a 00 6a 00} // EP packed locy 2
	
	condition:
		( $mz at 0 ) and 
		(
			$cyrptEP1 at pe.entry_point or
			$cyrptEP2 at pe.entry_point or 
			(any of ($inst*)) or 
			$deleteShadows
		)
}

rule RansomImportDetect
{
	meta:
		Description  = "Ransom.Gen.ab"
		ThreatLevel  = "3"
	condition:
		(pe.imports("Kernel32.dll", "FindFirstFileW") or pe.imports("Kernel32.dll", "FindFirstFileA")) and
		(pe.imports("Kernel32.dll", "FindNextFileW") or pe.imports("Kernel32.dll", "FindNextFileA")) and
		(pe.imports("Advapi32.dll", "CryptAcquireContextW") or pe.imports("Advapi32.dll", "CryptAcquireContextA")) and
		pe.imports("Advapi32.dll", "CryptEncrypt") and
		pe.imports("Advapi32.dll", "CryptGenRandom")
}

rule VMdetectMisc
{
	meta:
		Description = "Risk.VMDtc.sm"
		ThreatLevel = "3"

	strings:
		$vbox1 = "VBoxService" nocase ascii wide
		$vbox2 = "VBoxTray" nocase ascii wide
		$vbox3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase ascii wide
		$vbox4 = "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions" nocase ascii wide

		$wine1 = "wine_get_unix_file_name" ascii wide

		$vmware1 = "vmmouse.sys" ascii wide
		$vmware2 = "VMware Virtual IDE Hard Drive" ascii wide

		$miscvm1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase ascii wide
		$miscvm2 = "SYSTEM\\\\ControlSet001\\\\Services\\\\Disk\\\\Enum" nocase ascii wide

		$vmdrv1 = "hgfs.sys" ascii wide
		$vmdrv2 = "vmhgfs.sys" ascii wide
		$vmdrv3 = "prleth.sys" ascii wide
		$vmdrv4 = "prlfs.sys" ascii wide
		$vmdrv5 = "prlmouse.sys" ascii wide
		$vmdrv6 = "prlvideo.sys" ascii wide
		$vmdrv7 = "prl_pv32.sys" ascii wide
		$vmdrv8 = "vpc-s3.sys" ascii wide
		$vmdrv9 = "vmsrvc.sys" ascii wide
		$vmdrv10 = "vmx86.sys" ascii wide
		$vmdrv11 = "vmnet.sys" ascii wide

		$vmsrvc1 = "vmicheartbeat" ascii wide
		$vmsrvc2 = "vmicvss" ascii wide
		$vmsrvc3 = "vmicshutdown" ascii wide
		$vmsrvc4 = "vmicexchange" ascii wide
		$vmsrvc5 = "vmci" ascii wide
		$vmsrvc6 = "vmdebug" ascii wide
		$vmsrvc7 = "vmmouse" ascii wide
		$vmsrvc8 = "VMTools" ascii wide
		$vmsrvc9 = "VMMEMCTL" ascii wide
		$vmsrvc10 = "vmware" ascii wide
		$vmsrvc11 = "vmx86" ascii wide
		$vmsrvc12 = "vpcbus" ascii wide
		$vmsrvc13 = "vpc-s3" ascii wide
		$vmsrvc14 = "vpcuhub" ascii wide
		$vmsrvc15 = "msvmmouf" ascii wide
		$vmsrvc16 = "VBoxMouse" ascii wide
		$vmsrvc17 = "VBoxGuest" ascii wide
		$vmsrvc18 = "VBoxSF" ascii wide
		$vmsrvc19 = "xenevtchn" ascii wide
		$vmsrvc20 = "xennet" ascii wide
		$vmsrvc21 = "xennet6" ascii wide
		$vmsrvc22 = "xensvc" ascii wide
		$vmsrvc23 = "xenvdb" ascii wide

		$miscproc1 = "vmware2" ascii wide
		$miscproc2 = "vmount2" ascii wide
		$miscproc3 = "vmusrvc" ascii wide
		$miscproc4 = "vmsrvc" ascii wide
		$miscproc5 = "vboxservice" ascii wide
		$miscproc6 = "vboxtray" ascii wide
		$miscproc7 = "xenservice" ascii wide

		$vmware_mac_1a = "00-05-69"
		$vmware_mac_1b = "00:05:69"
		$vmware_mac_2a = "00-50-56"
		$vmware_mac_2b = "00:50:56"
		$vmware_mac_3a = "00-0C-29"
		$vmware_mac_3b = "00:0C:29"
		$vmware_mac_4a = "00-1C-14"
		$vmware_mac_4b = "00:1C:14"
		$virtualbox_mac_1a = "08-00-27"
		$virtualbox_mac_1b = "08:00:27"

	condition:
		2 of them
}

rule SandboxDetectMisc
{
	meta:
		Description = "Risk.SBDtc.sm"
		ThreatLevel = "3"

	strings:
		$sbxie1 = "sbiedll" nocase ascii wide

		$prodid1 = "55274-640-2673064-23950" ascii wide
		$prodid2 = "76487-644-3177037-23510" ascii wide
		$prodid3 = "76487-337-8429955-22614" ascii wide

		$proc1 = "joeboxserver" ascii wide
		$proc2 = "joeboxcontrol" ascii wide
	condition:
		any of them
}

rule avdetect_procs
{
	meta:
		Description = "Risk.AVDtc.sm"
		ThreatLevel = "3"

	strings:
		$proc2 = "LMon.exe" ascii wide
		$proc3 = "sagui.exe" ascii wide
		$proc4 = "RDTask.exe" ascii wide
		$proc5 = "kpf4gui.exe" ascii wide
		$proc6 = "ALsvc.exe" ascii wide
		$proc7 = "pxagent.exe" ascii wide
		$proc8 = "fsma32.exe" ascii wide
		$proc9 = "licwiz.exe" ascii wide
		$proc10 = "SavService.exe" ascii wide
		$proc11 = "prevxcsi.exe" ascii wide
		$proc12 = "alertwall.exe" ascii wide
		$proc13 = "livehelp.exe" ascii wide
		$proc14 = "SAVAdminService.exe" ascii wide
		$proc15 = "csi-eui.exe" ascii wide
		$proc16 = "mpf.exe" ascii wide
		$proc17 = "lookout.exe" ascii wide
		$proc18 = "savprogress.exe" ascii wide
		$proc19 = "lpfw.exe" ascii wide
		$proc20 = "mpfcm.exe" ascii wide
		$proc21 = "emlproui.exe" ascii wide
		$proc22 = "savmain.exe" ascii wide
		$proc23 = "outpost.exe" ascii wide
		$proc24 = "fameh32.exe" ascii wide
		$proc25 = "emlproxy.exe" ascii wide
		$proc26 = "savcleanup.exe" ascii wide
		$proc27 = "filemon.exe" ascii wide
		$proc28 = "AntiHook.exe" ascii wide
		$proc29 = "endtaskpro.exe" ascii wide
		$proc30 = "savcli.exe" ascii wide
		$proc31 = "procmon.exe" ascii wide
		$proc32 = "xfilter.exe" ascii wide
		$proc33 = "netguardlite.exe" ascii wide
		$proc34 = "backgroundscanclient.exe" ascii wide
		$proc35 = "Sniffer.exe" ascii wide
		$proc36 = "scfservice.exe" ascii wide
		$proc37 = "oasclnt.exe" ascii wide
		$proc38 = "sdcservice.exe" ascii wide
		$proc39 = "acs.exe" ascii wide
		$proc40 = "scfmanager.exe" ascii wide
		$proc41 = "omnitray.exe" ascii wide
		$proc42 = "sdcdevconx.exe" ascii wide
		$proc43 = "aupdrun.exe" ascii wide
		$proc44 = "spywaretermin" ascii wide
		$proc45 = "atorshield.exe" ascii wide
		$proc46 = "onlinent.exe" ascii wide
		$proc47 = "sdcdevconIA.exe" ascii wide
		$proc48 = "sppfw.exe" ascii wide
		$proc49 = "spywat~1.exe" ascii wide
		$proc50 = "opf.exe" ascii wide
		$proc51 = "sdcdevcon.exe" ascii wide
		$proc52 = "spfirewallsvc.exe" ascii wide
		$proc53 = "ssupdate.exe" ascii wide
		$proc54 = "pctavsvc.exe" ascii wide
		$proc55 = "configuresav.exe" ascii wide
		$proc56 = "fwsrv.exe" ascii wide
		$proc57 = "terminet.exe" ascii wide
		$proc58 = "pctav.exe" ascii wide
		$proc59 = "alupdate.exe" ascii wide
		$proc60 = "opfsvc.exe" ascii wide
		$proc61 = "tscutynt.exe" ascii wide
		$proc62 = "pcviper.exe" ascii wide
		$proc63 = "InstLsp.exe" ascii wide
		$proc64 = "uwcdsvr.exe" ascii wide
		$proc65 = "umxtray.exe" ascii wide
		$proc66 = "persfw.exe" ascii wide
		$proc67 = "CMain.exe" ascii wide
		$proc68 = "dfw.exe" ascii wide
		$proc69 = "updclient.exe" ascii wide
		$proc70 = "pgaccount.exe" ascii wide
		$proc71 = "CavAUD.exe" ascii wide
		$proc72 = "ipatrol.exe" ascii wide
		$proc73 = "webwall.exe" ascii wide
		$proc74 = "privatefirewall3.exe" ascii wide
		$proc75 = "CavEmSrv.exe" ascii wide
		$proc76 = "pcipprev.exe" ascii wide
		$proc77 = "winroute.exe" ascii wide
		$proc78 = "protect.exe" ascii wide
		$proc79 = "Cavmr.exe" ascii wide
		$proc80 = "prifw.exe" ascii wide
		$proc81 = "apvxdwin.exe" ascii wide
		$proc82 = "rtt_crc_service.exe" ascii wide
		$proc83 = "Cavvl.exe" ascii wide
		$proc84 = "tzpfw.exe" ascii wide
		$proc85 = "as3pf.exe" ascii wide
		$proc86 = "schedulerdaemon.exe" ascii wide
		$proc87 = "CavApp.exe" ascii wide
		$proc88 = "privatefirewall3.exe" ascii wide
		$proc89 = "avas.exe" ascii wide
		$proc90 = "sdtrayapp.exe" ascii wide
		$proc91 = "CavCons.exe" ascii wide
		$proc92 = "pfft.exe" ascii wide
		$proc93 = "avcom.exe" ascii wide
		$proc94 = "siteadv.exe" ascii wide
		$proc95 = "CavMud.exe" ascii wide
		$proc96 = "armorwall.exe" ascii wide
		$proc97 = "avkproxy.exe" ascii wide
		$proc98 = "sndsrvc.exe" ascii wide
		$proc99 = "CavUMAS.exe" ascii wide
		$proc100 = "app_firewall.exe" ascii wide
		$proc101 = "avkservice.exe" ascii wide
		$proc102 = "snsmcon.exe" ascii wide
		$proc103 = "UUpd.exe" ascii wide
		$proc104 = "blackd.exe" ascii wide
		$proc105 = "avktray.exe" ascii wide
		$proc106 = "snsupd.exe" ascii wide
		$proc107 = "cavasm.exe" ascii wide
		$proc108 = "blackice.exe" ascii wide
		$proc109 = "avkwctrl.exe" ascii wide
		$proc110 = "procguard.exe" ascii wide
		$proc111 = "CavSub.exe" ascii wide
		$proc112 = "umxagent.exe" ascii wide
		$proc113 = "avmgma.exe" ascii wide
		$proc114 = "DCSUserProt.exe" ascii wide
		$proc115 = "CavUserUpd.exe" ascii wide
		$proc116 = "kpf4ss.exe" ascii wide
		$proc117 = "avtask.exe" ascii wide
		$proc118 = "avkwctl.exe" ascii wide
		$proc119 = "CavQ.exe" ascii wide
		$proc120 = "tppfdmn.exe" ascii wide
		$proc121 = "aws.exe" ascii wide
		$proc122 = "firewall.exe" ascii wide
		$proc123 = "Cavoar.exe" ascii wide
		$proc124 = "blinksvc.exe" ascii wide
		$proc125 = "bgctl.exe" ascii wide
		$proc126 = "THGuard.exe" ascii wide
		$proc127 = "CEmRep.exe" ascii wide
		$proc128 = "sp_rsser.exe" ascii wide
		$proc129 = "bgnt.exe" ascii wide
		$proc130 = "spybotsd.exe" ascii wide
		$proc131 = "OnAccessInstaller.exe" ascii wide
		$proc132 = "op_mon.exe" ascii wide
		$proc133 = "bootsafe.exe" ascii wide
		$proc134 = "xauth_service.exe" ascii wide
		$proc135 = "SoftAct.exe" ascii wide
		$proc136 = "cmdagent.exe" ascii wide
		$proc137 = "bullguard.exe" ascii wide
		$proc138 = "xfilter.exe" ascii wide
		$proc139 = "CavSn.exe" ascii wide
		$proc140 = "VCATCH.EXE" ascii wide
		$proc141 = "cdas2.exe" ascii wide
		$proc142 = "zlh.exe" ascii wide
		$proc143 = "Packetizer.exe" ascii wide
		$proc144 = "SpyHunter3.exe" ascii wide
		$proc145 = "cmgrdian.exe" ascii wide
		$proc146 = "adoronsfirewall.exe" ascii wide
		$proc147 = "Packetyzer.exe" ascii wide
		$proc148 = "wwasher.exe" ascii wide
		$proc149 = "configmgr.exe" ascii wide
		$proc150 = "scfservice.exe" ascii wide
		$proc151 = "zanda.exe" ascii wide
		$proc152 = "authfw.exe" ascii wide
		$proc153 = "cpd.exe" ascii wide
		$proc154 = "scfmanager.exe" ascii wide
		$proc155 = "zerospywarele.exe" ascii wide
		$proc156 = "dvpapi.exe" ascii wide
		$proc157 = "espwatch.exe" ascii wide
		$proc158 = "dltray.exe" ascii wide
		$proc159 = "zerospywarelite_installer.exe" ascii wide
		$proc160 = "clamd.exe" ascii wide
		$proc161 = "fgui.exe" ascii wide
		$proc162 = "dlservice.exe" ascii wide
		$proc163 = "Wireshark.exe" ascii wide
		$proc164 = "sab_wab.exe" ascii wide
		$proc165 = "filedeleter.exe" ascii wide
		$proc166 = "ashwebsv.exe" ascii wide
		$proc167 = "tshark.exe" ascii wide
		$proc168 = "SUPERAntiSpyware.exe" ascii wide
		$proc169 = "firewall.exe" ascii wide
		$proc170 = "ashdisp.exe" ascii wide
		$proc171 = "rawshark.exe" ascii wide
		$proc172 = "vdtask.exe" ascii wide
		$proc173 = "firewall2004.exe" ascii wide
		$proc174 = "ashmaisv.exe" ascii wide
		$proc175 = "Ethereal.exe" ascii wide
		$proc176 = "asr.exe" ascii wide
		$proc177 = "firewallgui.exe" ascii wide
		$proc178 = "ashserv.exe" ascii wide
		$proc179 = "Tethereal.exe" ascii wide
		$proc180 = "NetguardLite.exe" ascii wide
		$proc181 = "gateway.exe" ascii wide
		$proc182 = "aswupdsv.exe" ascii wide
		$proc183 = "Windump.exe" ascii wide
		$proc184 = "nstzerospywarelite.exe" ascii wide
		$proc185 = "hpf_.exe" ascii wide
		$proc186 = "avastui.exe" ascii wide
		$proc187 = "Tcpdump.exe" ascii wide
		$proc188 = "cdinstx.exe" ascii wide
		$proc189 = "iface.exe" ascii wide
		$proc190 = "avastsvc.exe" ascii wide
		$proc191 = "Netcap.exe" ascii wide
		$proc192 = "cdas17.exe" ascii wide
		$proc193 = "invent.exe" ascii wide
		$proc194 = "Netmon.exe" ascii wide
		$proc195 = "fsrt.exe" ascii wide
		$proc196 = "ipcserver.exe" ascii wide
		$proc197 = "CV.exe" ascii wide
		$proc198 = "VSDesktop.exe" ascii wide
		$proc199 = "ipctray.exe" ascii wide
	condition:
		3 of them
}


rule dbgdetect_procs
{
	meta:
		Description = "Risk.DbgDtc.sm"
		ThreatLevel = "3"

	strings:
		$proc1 = "wireshark" nocase ascii wide
		$proc2 = "filemon" nocase ascii wide
		$proc3 = "procexp" nocase ascii wide
		$proc4 = "procmon" nocase ascii wide
		$proc5 = "regmon" nocase ascii wide
		$proc6 = "idag" nocase ascii wide
		$proc7 = "immunitydebugger" nocase ascii wide
		$proc8 = "ollydbg" nocase ascii wide
		$proc9 = "petools" nocase ascii wide

	condition:
		2 of them
}

rule dbgdetect_files
{
	meta:
		Description = "Risk.DbgDtc.sm"
		ThreatLevel = "3"

	strings:
		$file1 = "syserdbgmsg" nocase ascii wide
		$file2 = "syserboot" nocase ascii wide
		$file3 = "SICE" nocase ascii wide
		$file4 = "NTICE" nocase ascii wide
	condition:
		2 of them
}rule RiskNetFilterSampleA
{
	meta:
		Description  = "Risk.NetFilter.A.vb"
		ThreatLevel  = "5"

	strings:

		$ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\epfwwfp" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\epfwwfpr" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\nisdrv" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\symnets" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\klwfp" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\amoncdw8" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\amoncdw7" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\bdfwfpf_pc" ascii wide
        $ = "NFSDK Flow Established Callout" ascii wide
        $ = "Flow Established Callout" ascii wide
        $ = "NFSDK Stream Callout" ascii wide
        $ = "Stream Callout" ascii wide
        $ = "\\Device\\CtrlSM" ascii wide
        $ = "\\DosDevices\\CtrlSM" ascii wide

	condition:
		all of them
}
rule RogueDownloaderLoaderAVSoftA
{
	meta:
		Description  = "Trojan.Loader.sm"
		ThreatLevel  = "5"

	strings:
		$ = "/info.php?idd=" ascii wide
		$ = "{95B8F20E-4BC6-4E22-9442-BFB69ED62879}" ascii wide
		//$ = "CheckExeSignatures" ascii wide
		//$ = "RunInvalidSignatures" ascii wide
		$ = "ELEVATECREATEPROCESS" ascii wide
		$ = "srvdev.dll" ascii wide
		//$ = "EntryPoint" ascii wide

	condition:
		3 of them
}

rule RogueModuleAVSoftA
{
	meta:
		Description  = "Rogue.AVSoft.sm"
		ThreatLevel  = "5"

	strings:
		$ = "sec-red-alert-s.gif" ascii wide
		$ = "sec-red-alert-b.gif" ascii wide
		$ = "scaning.gif" ascii wide
		$ = "scaning-stopped.gif" ascii wide
		$ = "rezult-table-head-bg.gif" ascii wide
		$ = "banner-get-protection.gif" ascii wide
		$ = "netalrt.htm" ascii wide
		$ = "alrt.htm" ascii wide

		$hex1 = { e8 ?? ?? ?? ?? 83 ?? ?? ?? ?? 74 ?? 83 ?? ?? ?? ?? ?? ?? 74 ?? e8 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 73 ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 84 c0 75 ?? e8 ?? ?? ?? ?? 6a 1e 99 59 f7 f9 83 c2 14 69 d2 60 ea 00 00 52 ff d7 e8 ?? ?? ?? ?? 83 f8 01 75 ?? e8 ?? ?? ?? ??}

	condition:
		(3 of them) or ( any of ($hex*))
}
rule RogueBraviaxSampleA
{
    meta:
        Description = "Rogue.Braviax.sm"
        ThreatLevel = "5"

    strings:
		$ = "background_gradient_red.jpg" ascii wide
		$ = "red_shield_48.png" ascii wide
		$ = "pagerror.gif" ascii wide
		$ = "green_shield.png" ascii wide
		$ = "refresh.gif" ascii wide
		$ = "red_shield.png" ascii wide
		$ = "avp:scan" ascii wide
		$ = "avp:site" ascii wide
		$str1 = "Trojan-BNK.Win32.Keylogger.gen" ascii wide
		$str2 = "Trojan-PSW.Win32.Coced.219" ascii wide
		$str3 = "Email-Worm.Win32.Eyeveg.f" ascii wide
		$str4 = "Virus.BAT.Batalia1.840" ascii wide
		$str5 = "Trojan-SMS.SymbOS.Viver.a" ascii wide
		$str6 = "Trojan-Spy.HTML.Bankfraud.jk" ascii wide
		$str7 = "glohhstt7.com" ascii wide
		//$str8 = "Zorton" ascii wide
		//$str9 = "Rango" ascii wide
		//$str10 = "Sirius" ascii wide
		//$str11 = "A-Secure" ascii wide
		$str12 = "%1 Protection 201" ascii wide
		$str13 = "%1 Antivirus 201" ascii wide
		$str14 = "siriuc2014.com" ascii wide
		$str15 = "siriucs2016.com" ascii wide
		$str16 = "zorton2016.com" ascii wide
		$str17 = "zorton2015.com" ascii wide
		$str18 = "stormo10.com" ascii wide
		$str19 = "fscurat20.com" ascii wide
		$str20 = "fscurat21.com" ascii wide

    condition:
        (3 of them) or (any of ($str*))
}rule RogueFakePAVSample
{
    meta:
        Description = "Rogue.FakePAV.sm"
        ThreatLevel = "5"

    strings:
		$ = "ZALERT" ascii wide
		$ = "ZAPFrm" ascii wide
		$ = "ZAbout" ascii wide
		$ = "ZAutoRunFrame" ascii wide
		$ = "ZCheckBox" ascii wide
		$ = "ZCplAll" ascii wide
		$ = "ZFogWnd" ascii wide
		$ = "ZFrameDEt" ascii wide
		$ = "ZIEWnd" ascii wide
		$ = "ZMainFrame" ascii wide
		$ = "ZMainWnd" ascii wide
		$ = "ZOptionsFrame" ascii wide
		$ = "ZProcessFrame" ascii wide
		$ = "ZProgressBar" ascii wide
		$ = "ZPromo" ascii wide
		$ = "ZReg" ascii wide
		$ = "ZResFR" ascii wide
		$ = "ZServiceFrame" ascii wide
		$ = "ZUpdate" ascii wide
		$ = "ZWarn" ascii wide

    condition:
        any of them
}rule RogueFakeDefenderSample
{
	meta:
		Description  = "Rogue.FakeDef.sm"
		ThreatLevel  = "5"

	strings:
		$a = "pcdfdata" 		ascii wide
		$b = "toplevel_pcdef" 	ascii wide
		
		$ = "%spld%d.exe" ascii wide
		$ = "avsrun.exe" ascii wide
		$ = "avsdel.exe" ascii wide
		
		$ = "vl.bin" ascii wide
		$ = "reginfo.bin" ascii wide
		
		$ = "%s%s.lnk" ascii wide
		$ = "%sRemove %s.lnk" ascii wide
		$ = "Uninstaller application" ascii wide
		$ = "%s%s Help and Support.lnk" ascii wide
		
		$ = "pavsdata" ascii wide
		$ = "avsmainwnd" ascii wide
		$ = "avsdsvc" ascii wide
		$ = "ovcf" ascii wide
		
		$ = "Global\\avsinst" ascii wide
		$ = "Global\\avscfglock" ascii wide
		$ = "\\loc\\reg\\conn\\activate" ascii wide
		$ = "\\forms\\alerts\\vulner" ascii wide
		$ = "\\forms\\alerts\\hack" ascii wide
		
		$ = "Software\\Classes\\.exe" ascii wide
		
		$ = "%s was infected with %s and has been successfully repaired" ascii wide
		$ = "Attack %s from remote host %d.%d.%d.%d has been successfully blocked" ascii wide
			
		$ = "http://%s/api/ping?stage=1&uid=%S&id=%d&subid=%d&os=%d&avf=%d" ascii wide
		$ = "http://%s/api/ping?stage=2&uid=%S&success=%d" ascii wide
		$ = "http://%s/api/ping?stage=3&uid=%S" ascii wide
		$ = "http://%s/content/scc" ascii wide
		$ = "http://%s/postload2/?uid=%S" ascii wide
		$ = "http://%S/api/test" ascii wide
		$ = "http://%s/load/?uid=%S" ascii wide
		$ = "http://%s/html/viruslist/?uid=%S" ascii wide
		$ = "https://%s/billing/key/?uid=%S" ascii wide
		$ = "https://%s/html/billing/?uid=%S" ascii wide

	condition:
		3 of them
}

rule RogueFakeReanInternetSecuritySample
{
	meta:
		Description  = "Rogue.FakeRean.sm"
		ThreatLevel  = "5"

	strings:
		$ = "VB82ea936a-6aa61dbf" ascii wide
		$ = "VBOX HARDDISK" ascii wide
		$ = "avbase.dat" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "ORDER #:" ascii wide
		$ = "Thank you, the program is now registered!" ascii wide
		$ = "To continue please restart the program. Press OK to close the program." ascii wide
		$ = "Wrong activation code! Please check and retry" ascii wide
		$ = "license. As soon as you complete the activation you will" ascii wide
		$ = "This option is available only in the activated version of " ascii wide
		$ = "You must activate the program by entering registration information " ascii wide
		$ = "has detected that a new Threat Database is available." ascii wide
		$ = "items are critical privacy compromising content"
		$ = "items is medium privacy threats" ascii wide
		$ = "items are junk content of low privacy threats" ascii wide
		$ = "has detected a leak of your files though the Internet. " ascii wide
		$ = "We strongly recommend that you block the attack immediately" ascii wide
		$ = "All threats has been succesfully removed." ascii wide
		$ = "Attention! We strongly recommend that you activate " ascii wide
		$ = "for the safety and faster running of your PC." ascii wide
		$ = "No new update available" ascii wide
		$ = "Could not connect to server!" ascii wide
		$ = "New updates are installed successfully!" ascii wide
		$ = "Security Warning!" ascii wide
		$ = "Malicious program has been detected." ascii wide
		$ = "Click here to protect your computer." ascii wide
		$ = "is infected by W32/Blaster.worm" ascii wide
		$ = "$$$$$$$$.bat" ascii wide
		$ = "Completed!" ascii wide
		$ = "Antivirus software uninstalled successfully" ascii wide
		$ = "Antivirus uninstall is not success. Please try again..." ascii wide
		$ = "-uninstall" ascii wide
		$ = "_MUTEX" ascii wide
		$ = "/min" ascii wide
		
	condition:
		7 of them
}

rule RogueUnknownFakeAV
{
	meta:
		Description  = "Rogue.FakeRean.rc"
		ThreatLevel  = "5"
		
	strings:
		$a = "S:\\appointed\\commanding\\general\\Moravia\\Image[01].exe" ascii wide
		$b = "Dresden blockade" ascii wide
		$c = "37592837532" ascii wide
		$d = "39874598234" ascii wide
		$e = "465234750238947532649587203948523-4572304750329458-23459723450-23457" ascii wide
		
	condition:
		($a and $b) or ($c and $d) or $e
}

rule RoguePCDefender
{
	meta:
		Description  = "Rogue.FakeDef.rc"
		ThreatLevel  = "5"
		
	strings:
		$hex0 = { 8A 4A 01 56 57 33 FF 47 8B C7 8D 72 03 85 C0 74 28 80 C1 0B 80 F9 5A 7E 11 0F BE C1 83 E8 41 6A 19 99 59 F7 F9 80 C2 41 8A CA 33 C0 38 0E 0F 94 C0 47 46 46 83 FF 10 7C D4 5F 5E C3 }
		
	condition:
		any of ($hex*)
}rule RogueFakeSysDefSample
{
	meta:
		Description  = "Rogue.FakeSysDef.sm"
		ThreatLevel  = "5"

	strings:
		$ = "smtmp" ascii wide
		$ = "attrib -h"  ascii wide
		$ = "%s\\license.dat"  ascii wide
		$ = "Thank you for purchasing %s"    ascii wide
		$ = "%s\\%s_License.txt" ascii wide
		$ = "Bad sectors" ascii wide
		$ = "Lost cluster chains" ascii wide
		$ = "Relocate bad sectors: " ascii wide
		$ = "Fix corrupted files: " ascii wide
		$ = "Fix cluster chain: " ascii wide
		$ = "No errors found. Disk%s health summary %d%%." ascii wide
		$ = "Error 0x00000024 - %s_FILE_SYSTEM" ascii wide
		$ = "Verifying disk consistency..." ascii wide
		$ = "Hard drive spin failure detected" ascii wide
		$ = "Checking S.M.A.R.T. attributes" ascii wide
		$a = "S.M.A.R.T reports" ascii wide
		$ = "Checking HDD surface for bad sectors.." ascii wide
		$ = "Scanning sectors 0x%04X-0x%04X..." ascii wide
		$ = "Check cancelled." ascii wide
		$ = "Hard disk error detected" ascii wide
		$ = "Repair volumes" ascii wide
		$ = "Hard disk verification completed. No errors found." ascii wide
		$ = "Exception Processing Message 0x%08X Parameters" ascii wide
		$ = "Windows - Read error" ascii wide
		$ = "File system on local disk %s contains critical errors" ascii wide
		$ = "explorer.exe - Corrupt Disk" ascii wide
		$ = "svchost.exe - Corrupt Disk" ascii wide

	condition:
		(3 of them) or $a
}rule RogueWin32LiveSecurityProfessional
{
	meta:
		Description  = "Rogue.LiveSP.sm"
		ThreatLevel  = "5"
	strings:
		$ = "W32.SillyFDC.BDQ" ascii wide
		$ = "Trojan.Peancomm" ascii wide
		$ = "Adware.Borlan" ascii wide
		$ = "Trojan.Exprez" ascii wide
		$ = "Sunshine.B" ascii wide
		$ = "SecurityRisk.URLRedir" ascii wide
		$ = "Spyware.Ezurl" ascii wide
		$ = "W32.Azero.A" ascii wide
		$ = "W32.Downloadup.B" ascii wide
		$ = "Hacktool.Unreal.A" ascii wide
		$ = "Backdoor.Rustock.B" ascii wide
		$ = "Infostealer.Snifula.B" ascii wide
		$ = "Adware.FCHelp" ascii wide
		$ = "Adware.Invinciblekey" ascii wide
		$ = "Packed.Dromedan!gen5" ascii wide
		$ = "Downloader.Jadelile" ascii wide
		$ = "SecShieldFraud!gen7" ascii wide
		$ = "Trojan.Komodola" ascii wide
		$ = "W32.Stekct" ascii wide
		$ = "Packed.Generic.368" ascii wide
		$ = "VirusDoctor!gen12" ascii wide
		$ = "UnlockAV" ascii wide
		$ = "Sign Up in Live Security Professional" ascii wide
		$ = "General security:" ascii wide
		$ = "Real-Time Shields:" ascii wide
		$ = "Self-protection from malware:" ascii wide
		$ = "Definitions auto updates:" ascii wide
		$ = "Virus definition version:" ascii wide
		$ = "Program version:" ascii wide
		$ = "Live Security Professional %s." ascii wide
		$ = "You have a license" ascii wide
		$ = "Your system is protected from possible threats." ascii wide
		$ = "3.13.44.20" ascii wide
		$ = "Protection level:" ascii wide
		$ = "Your computer is fully protected." ascii wide
		$ = "Your protection against viruses and spyware is weak" ascii wide
		$ = "You must enter the serial number that came to your email to activate your license." ascii wide
		$ = "Live Security Professional - Unregistered version" ascii wide
		$ = "Scan stopped..." ascii wide
		$ = "Scan paused..." ascii wide
		$ = "http://185.6.80.65/index.php?r=checkout" ascii wide
		$ = "To complete the registration, check your data for correctness." ascii wide
		$ = "You have successfully signed up and choose a license. After confirming the payment (about 10 minutes), you get a completely secure system." ascii wide
		$ = "Live Security Professional has blocked" ascii wide
		$ = "Live security professional" ascii wide
		$ = "Successfully Cleared!" ascii wide
		$ = "DETECTED VIRUSES" ascii wide
		$ = "List of detected viruses." ascii wide
		$ = "Total infected:" ascii wide
		$ = "10% of the viruses were treated free. For the cure of all viruses, you must purchase a license Pro or Pro Plus." ascii wide
	condition:
		5 of them
}rule RogueSpywareDefenderSample
{
	meta:
		Description  = "Rogue.SDef.sm"
		ThreatLevel  = "5"

	strings:
		$str1 = "/get_two.php?" ascii wide
		$str2 = "spyware-defender.com" ascii wide
		$str3 = "Spyware Defender 2014" ascii wide
		$str4 = "Antivirus MAC 2014" ascii wide
		$str5 = "Antivirus WIN 2014" ascii wide
		$ = "Delete" ascii wide
		$ = "NoRemove" ascii wide
		$ = "ForceRemove" ascii wide
		$ = "RunInvalidSignatures" ascii wide
		$ = "CheckExeSignatures" ascii wide
	condition:
		(5 of them) or (any of ($str*))
}rule RogueWin32SystemDoctorA
{
	meta:
		Description  = "Rogue.SysDoct.rc"
		ThreatLevel  = "5"
	strings:
		$hex0 = { 55 8b ec 83 ec 7c a1 ?? ?? ?? ?? 33 c5 89 ?? ?? 56 68 90 d0 47 00 8d ?? ?? e8 ?? ?? ?? ?? 83 ?? ?? ?? 8b ?? ?? 73 ?? 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 8d ?? ?? 83 f8 ff 74 ?? 6a 00 6a 01 e8 ?? ?? ?? ?? 33 c0 8b ?? ?? 33 cd 5e e8 ?? ?? ?? ?? c9 c3 53 57 33 db 53 6a 01 e8 ?? ?? ?? ?? be a4 d0 47 00 8d ?? ?? a5 a4 be ac d0 47 00 8d ?? ?? a5 a4 be b4 d0 47 00 8d ?? ?? a5 66 ?? a4 be bc d0 47 00 8d ?? ?? a5 a5 66 ?? a4 be 90 88 45 00 8d ?? ?? a5 a5 a5 a5 be 00 10 00 00 56 e8 ?? ?? ?? ?? 59 6a 02 53 89 ?? ?? 53 8d ?? ?? 50 c7 ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8b f8 83 ff ff 0f ?? ?? ?? ?? ?? 8d ?? ?? 50 53 57 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 8d ?? ?? 50 56 8b ?? ?? 56 8d ?? ?? 50 6a 0c 8d ?? ?? 50 57 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 56 ff ?? ?? ?? ?? ?? 8d ?? ?? 50 56 e8 ?? ?? ?? ?? 59 59 85 c0 75 ?? 8d ?? ?? 50 56 e8 ?? ?? ?? ?? 59 59 85 c0 75 ?? 8d ?? ?? 50 56 e8 ?? ?? ?? ?? 59 59 85 c0 75 ?? 8d ?? ?? 50 56 e8 ?? ?? ?? ?? 59 59 85 c0 74 ?? 33 db 43 56 e8 ?? ?? ?? ?? 59 5f 8b c3 5b e9 ?? ?? ?? ?? 8b ?? ?? eb ?? }
		$ = "http://sys-doctor.com" ascii wide
		$ = "AA39754E-715219CE" ascii wide
		$ = "System Doctor" ascii wide
		$ = "C:\\sd.dbg" ascii wide
		$ = "C:\\sd1.dbg" ascii wide
	condition:
		(2 of them) or (any of ($hex*))
}

rule RogueWin32FufelAVA
{
	meta:
		Description  = "Rogue.FufelAV.sm"
		ThreatLevel  = "5"
	strings:
		$ = "avp:buy" ascii wide
		$ = "avp:scan" ascii wide
		$ = "Protection software" ascii wide
		$ = "Invalid registration key!" ascii wide
		$ = "Unprotected mode request" ascii wide
		$ = "Are you sure want to continue in unprotected mode?" ascii wide
		$ = "I have serial key" ascii wide
		$ = "Continue unprotected" ascii wide
		$ = "trying to infect your files" ascii wide
		$ = "Your computer was attacked from" ascii wide
		$ = "Attack was blocked" ascii wide
		$ = "Please register product to block hackers attack" ascii wide
		$ = "Scanning completed. No threads found." ascii wide
		$ = "Scanning completed. Cleanup is required." ascii wide
		$ = "Warning! %d Infections found!" ascii wide
		$ = "Registered version" ascii wide
		$ = "Unregistered version (Please register)" ascii wide
		$ = "Cured" ascii wide
		$ = "Infected process" ascii wide
		$str_0 = "Sinergia Cleaner" ascii wide
		$str_1 = "Sinergia software.lnk" ascii wide
		
		$str_2 = "fufel-av-2.com" ascii wide
		$str_3 = "fufel-av.com" ascii wide
	condition:
		(3 of them) or (any of ($str_*))
}
rule RogueWinwebsecSample
{
	meta:
		Description  = "Rogue.Winwebsec.sm"
		ThreatLevel  = "5"

	strings:
		$a = "%s%s\\%s.ico" ascii wide
		$b = "%s%s\\%s.exe" ascii wide
	condition:
		$a or $b
}

rule RogueSShieldSample
{
	meta:
		Description  = "Rogue.SShield.sm"
		ThreatLevel  = "5"

	strings:
		$a = "64C665BE" 	wide
		$b = "BC0172B25DF2" wide
	condition:
		$a or $b
}rule TrojanWin32AntivarSample
{
	meta:
		Description  = "Trojan.Antivar.sm"
		ThreatLevel  = "5"
	strings:
		$ = "ServerNabs4" ascii wide
		$ = "\\system32\\antivar.exe" ascii wide
	condition:
		any of them
}rule TrojanDownloaderCbeplaySample
{
	meta:
		Description  = "Trojan.Cbeplay.sm"
		ThreatLevel  = "5"

	strings:
		$ = "wireshark.exe" ascii wide
		$ = "pstorec.dll" ascii wide
		$ = "ROOT\\SecurityCenter2" ascii wide
		$ = "Select * from AntiVirusProduct" ascii wide
		$ = "SbieDll.dll" ascii wide
		$ = "OPEN %s.mp3 TYPE MpegVideo ALIAS MP3" ascii wide
		$ = "PLAY MP3 wait" ascii wide
		$ = "CLOSE MP3" ascii wide
		$ = "VIRTUALBOX" ascii wide
		$ = "VideoBiosVersion" ascii wide
		$ = "QEMU" ascii wide
		$ = "VMWARE" ascii wide
		$ = "VBOX" ascii wide
		$ = "VIRTUAL" ascii wide
		$ = "taskmgr.exe" ascii wide
		$ = "explorer.exe" ascii wide
		$ = "Program Manager" ascii wide
		$ = "Shell_TrayWnd" ascii wide
		$ = "FriendlyName" ascii wide
		$ = "Capture Filter" ascii wide
		$ = "SampleGrab" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot" ascii wide
		$ = "Hello, visitor from: <strong>" ascii wide
		$ = "SendVoucher" ascii wide
		$ = "winver" ascii wide
		$ = "AVID" ascii wide
		$ = "Emsisoft" ascii wide
		$ = "Lavasoft" ascii wide
		$ = "avast" ascii wide
		$ = "Avira" ascii wide
		$ = "BitDef" ascii wide
		$ = "COMODO" ascii wide
		$ = "F-Secure" ascii wide
		$ = "G Data" ascii wide
		$ = "Kaspersky" ascii wide
		$ = "McAfee" ascii wide
		$ = "ESET" ascii wide
		$ = "Norton" ascii wide
		$ = "Microsoft Security Essentials" ascii wide
		$ = "Panda" ascii wide
		$ = "Sophos" ascii wide
		$ = "Trend Micro" ascii wide
		$ = "Symantec" ascii wide
		$ = "BullGuard" ascii wide
		$ = "VIPRE" ascii wide
		$ = "Webroot" ascii wide
	condition:
		8 of them
}rule TrojanChangeStartPageSampleA
{
 meta:
  Description  = "Trojan.CStartPage.sm"
  ThreatLevel  = "5"

 strings:
	$ = "chrome.exe" ascii wide
	$ = "urls_to_restore_on_startup" ascii wide
	$ = "restore_on_startup" ascii wide
	$ = "restore_on_startup_migrated" ascii wide
	$ = "urls_to_restore_on_startup" ascii wide
	$ = "translate_accepted_count" ascii wide
	$ = "translate_denied_count" ascii wide
	$ = "translate_site_blacklist" ascii wide
	$ = "netsh firewall add allowedprogram" ascii wide
	$ = "homepage_is_newtabpage" ascii wide
	$ = "Start Page" ascii wide
	$ = "user_pref(%cbrowser.startup.homepage%c" ascii wide
	$ = "%ws\\mozilla\\firefox\\profiles" ascii wide
	$ = "c:\\windows\\sms.exe" ascii wide
 condition:
	3 of them
}
rule TrojanWin32CitadelSampleA
{
	meta:
		Description  = "Trojan.Citadel.sm"
		ThreatLevel  = "5"

	strings:
		$a = "Coded by BRIAN KREBS for personal use only. I love my job & wife." ascii wide
		$hex_string = {85 C0 7? ?? 8A 4C 30 FF 30 0C 30 48 7?}
		$ = "softpc.new" ascii wide
		$ = "CS:%04x IP:%04x OP:%02x %02x %02x %02x %02x" ascii wide

	condition:
		any of them
}rule TrojanWin32ComfooSample
{
	meta:
		Description  = "Trojan.Comfoo.sm"
		ThreatLevel  = "5"

	strings:
		$ = "exclusiveinstance12" ascii wide
		$ = "MYGAMEHAVESTART" ascii wide
		$ = "MYGAMEHAVEstarted" ascii wide
		$ = "MYGAMEHAVESTARTEd" ascii wide
		$ = "MYGAMEHAVESTARTED" ascii wide
		$ = "thisisanewfirstrun" ascii wide
		$ = "THISISASUPERNEWGAMENOWBEGIN" ascii wide
		$ = "thisisnewtrofor024" ascii wide

		$ = "cabinet.dll" ascii wide
		$ = "09lkjds" ascii wide
		$ = "perfdi.ini" ascii wide
		$ = "msobj.sys" ascii wide
		$ = "usbak.sys" ascii wide
		$ = "\\\\.\\DevCtrlKrnl" ascii wide
		$ = "THIS324NEWGAME" ascii wide
		$ = "watchevent29021803" ascii wide
		$ = "iamwaitingforu653890" ascii wide
		$ = "Call to GetAdaptersInfo failed. Return Value" ascii wide
		$ = "Hard Disk(%s--LocalDisk)" ascii wide
		$ = "Total size: %I64d (MB)" ascii wide

		$ = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii wide

		$hex0 = { 6a ff 68 1b 04 01 10 64 ?? ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 51 56 57 68 30 17 00 00 e8 ?? ?? ?? ?? 83 c4 04 89 ?? ?? ?? 85 c0 c7 ?? ?? ?? ?? ?? ?? ?? 74 ?? 8b c8 e8 ?? ?? ?? ?? 8b f0 eb ?? 33 f6 8b ?? 6a 01 8b ce c7 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? bf 30 3b 01 10 83 c9 ff 33 c0 8b ?? f2 ?? f7 d1 49 51 68 30 3b 01 10 8b ce ff ?? ?? 8b ?? 68 81 3e 00 00 8b ce ff ?? ?? 8b ?? ?? ?? 8b ?? 50 8b ce ff ?? ?? 8b ?? ?? ?? 8b ?? 50 8b ce ff ?? ?? 56 e8 ?? ?? ?? ?? 8b f8 83 c4 04 f7 df 1b ff 47 85 f6 74 ?? 8b ce e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 04 8b ?? ?? ?? 8b c7 5f 5e 64 ?? ?? ?? ?? ?? ?? 83 c4 10 c3}
		$hex1 = { 55 56 57 6a 08 33 ed e8 ?? ?? ?? ?? 8b f0 83 c4 04 85 f6 0f ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 89 ?? ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 68 7f 03 0f 00 55 68 94 32 01 10 89 ?? ?? ff ?? ?? ?? ?? ?? 8b f8 85 ff 74 ?? 53 57 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 68 ff 01 0f 00 55 55 68 e8 30 01 10 ff ?? ?? ?? ?? ?? 8b d8 85 db 74 ?? 53 ff ?? ?? ?? ?? ?? 85 c0 74 ?? bd 01 00 00 00 53 ff ?? ?? ?? ?? ?? 57 ff ?? ?? ?? ?? ?? 85 ed 5b 74 ?? 8b c6 5f 5e 5d c3}
		$hex2 = { 53 53 6a 03 53 53 68 00 00 00 c0 68 78 33 01 10 ff ?? ?? ?? ?? ?? 89 ?? ?? 83 f8 ff 75 ?? 33 c0 8b ?? ?? 64 ?? ?? ?? ?? ?? ?? 5f 5e 5b 8b e5 5d c3 89 ?? ?? 89 ?? ?? 89 ?? ?? be 88 33 01 10 8b c7 8a ?? 8a ca 3a ?? 75 ?? 3a cb 74 ?? 8a ?? ?? 8a ca 3a ?? ?? 75 ?? 83 c0 02 83 c6 02 3a cb 75 ?? 33 c0 eb ?? 1b c0 83 d8 ff 3b c3 75 ?? 89 ?? ?? eb ?? 57 ff ?? ?? ?? ?? ?? 89 ?? ?? 83 f8 ff 74 ?? 8b ?? ?? 50 ff ?? ?? ?? ?? ?? 66 ?? ?? ?? 53 8d ?? ?? 51 6a 04 8d ?? ?? 52 6a 06 8d ?? ?? 50 8b ?? ?? 56 8b ?? ?? 51 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 81 fe c8 20 22 00 75 ?? c7 ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? 8b ?? ?? 64 ?? ?? ?? ?? ?? ?? 5f 5e 5b 8b e5 5d c3}

	condition:
		(3 of them) or (any of ($hex*))
}rule TrojanBotnetWin32CutwailSample
{
	meta:
		Description  = "Trojan.Cutwail.sm"
		ThreatLevel  = "5"

	strings:
		$ = "PreLoader.pdb" ascii wide
		$ = "magadan21"  ascii wide
		$ = "RkInstall.pdb"  ascii wide
		$ = "InnerDrv.pdb"    ascii wide
		$ = "Protect.pdb" ascii wide
		$ = "MailerApp.pdb" ascii wide
		$ = "revolution6" ascii wide
		$ = "bot25" ascii wide
	condition:
		any of them
}rule TrojanDllpatcherA
{
   meta:
       Description = "Trojan.Dllpatcher.vb"
       ThreatLevel = "5"

   strings:
		$str1 = "Global\\Matil da"  ascii wide
		$str2 = "Global\\Nople Mento"  ascii wide
		$str3 = "%s\\System32\\dnsapi.dll"  ascii wide
		$str4 = "%s\\SysWOW64\\dnsapi.dll"  ascii wide

   condition:
      3 of them
}
rule TrojanDownloaderWin32KaraganySampleA
{
	meta:
		Description  = "Trojan.Karagany.sm"
		ThreatLevel  = "5"
	strings:
		$hex0 = { e8 ?? ?? ?? ?? 68 b4 05 00 00 e8 ?? ?? ?? ?? 83 c4 04 c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ?? ?? 99 b9 05 00 00 00 f7 f9 89 ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 75 ?? 68 c0 24 40 00 8b ?? ?? ?? ?? ?? 52 ff ?? ?? ?? ?? ?? 83 c4 08 eb ?? 83 ?? ?? ?? ?? ?? ?? 75 ?? 68 78 24 40 00 a1 ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 83 c4 08 eb ?? 83 ?? ?? ?? ?? ?? ?? 75 ?? 68 30 24 40 00 8b ?? ?? ?? ?? ?? 51 ff ?? ?? ?? ?? ?? 83 c4 08 eb ?? 83 ?? ?? ?? ?? ?? ?? 75 ?? 68 e8 23 40 00 8b ?? ?? ?? ?? ?? 52 ff ?? ?? ?? ?? ?? 83 c4 08 eb ?? 83 ?? ?? ?? ?? ?? ?? 75 ?? 68 a0 23 40 00 a1 ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 83 c4 08 8d ?? ?? ?? ?? ?? 51 68 00 03 00 84 6a 00 6a 00 8b ?? ?? ?? ?? ?? 52 8b ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 74 ?? 83 ?? ?? ?? ?? ?? ??}
		$hex1 = { 55 8b ec 83 ec 18 e8 ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 04 a3 ?? ?? ?? ?? 68 d0 21 40 00 8b ?? ?? 51 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 6a 00 68 38 23 40 00 ff ?? ?? ?? ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? ?? eb ?? 8b ?? ?? 83 c2 01 89 ?? ?? 83 ?? ?? ?? 73 ?? 8b ?? ?? 8b ?? ?? ?? ?? ?? ?? 51 8b ?? ?? 52 ff ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? ?? eb ?? 6a 00 6a 00 68 2c 23 40 00 ff ?? ?? ?? ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? ?? eb ?? 8b ?? ?? 83 c2 01 89 ?? ?? 83 ?? ?? ?? 73 ?? 8b ?? ?? 8b ?? ?? ?? ?? ?? ?? 51 8b ?? ?? 52 ff ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? ?? eb ?? 6a 00 6a 00 68 20 23 40 00 ff ?? ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? ?? ?? ?? 52 8b ?? ?? 50 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 51 8b ?? ?? 52 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 8b ?? ?? 51 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 6a 00 68 14 23 40 00 ff ?? ?? ?? ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? ?? eb ?? 8b ?? ?? 83 c2 01 89 ?? ?? 83 ?? ?? ?? 73 ?? 8b ?? ?? 8b ?? ?? ?? ?? ?? ?? 51 8b ?? ?? 52 ff ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? ?? eb ?? 6a 00 6a 00 68 04 23 40 00 ff ?? ?? ?? ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? ?? eb ?? 8b ?? ?? 83 c2 01 89 ?? ?? 83 ?? ?? ?? 73 ?? 8b ?? ?? 8b ?? ?? ?? ?? ?? ?? 51 8b ?? ?? 52 ff ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? ?? eb ?? 8b e5 5d c3}
		$hex2 = { 55 8b ec 81 ec 20 04 00 00 a1 ?? ?? ?? ?? 89 ?? ?? 68 e0 30 40 00 68 48 23 40 00 8d ?? ?? ?? ?? ?? 51 ff ?? ?? 83 c4 0c 6a 00 6a 00 8d ?? ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 0c b8 01 00 00 00 8b e5 5d c3}
	condition:
		any of ($hex*)
}

rule TrojanDownloaderWin32WaledacSampleR
{
	meta:
		Description  = "Trojan.Waledac.sm"
		ThreatLevel  = "5"
	strings:
		$hex0 = { 55 8b ec 81 ec 6c 02 00 00 56 57 68 80 00 00 00 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 68 1c 21 40 00 8d ?? ?? ?? ?? ?? 50 ff d6 e8 ?? ?? ?? ?? 8d ?? ?? 51 50 e8 ?? ?? ?? ?? 8b ?? ?? 59 59 8b ?? ?? 8d ?? ?? ?? 50 8d ?? ?? ?? ?? ?? 50 ff d6 8d ?? ?? 50 e8 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? 50 ff d6 33 f6 56 56 6a 02 56 56 68 00 00 00 40 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8b f8 3b fe 75 ?? 32 c0 eb ?? 56 8d ?? ?? 50 53 ff ?? ?? 57 ff ?? ?? ?? ?? ?? 57 ff ?? ?? ?? ?? ?? 39 ?? ?? 75 ?? 6a 44 5f 57 8d ?? ?? 56 50 e8 ?? ?? ?? ?? 83 c4 0c 33 c0 66 ?? ?? ?? 8d ?? ?? 50 8d ?? ?? 50 56 56 56 56 56 56 8d ?? ?? ?? ?? ?? 50 56 89 ?? ?? c7 ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? f7 d8 1b c0 f7 d8 5f 5e c9 c3 55}
		$hex1 = { 55 8b ec 83 e4 f8 83 ec 10 56 57 e8 ?? ?? ?? ?? be 10 30 40 00 56 68 02 02 00 00 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 56 6a 02 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 56 68 01 01 00 00 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 6a ff ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? be 30 21 40 00 8d ?? ?? ?? a5 a5 59 a3 ?? ?? ?? ?? a5 8d ?? ?? ?? 50 68 40 21 40 00 a4 e8 ?? ?? ?? ?? 59 59 84 c0 75 ?? 8d ?? ?? ?? 50 68 4c 21 40 00 e8 ?? ?? ?? ?? 59 59 ff ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 ff ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 5f 33 c0 5e 8b e5 5d c3}
		$hex2 = { 55 8b ec 51 83 ?? ?? ?? 53 8b ?? ?? ?? ?? ?? 56 57 bf 00 90 01 00 eb ?? 7c ?? 8b ?? ?? 56 ff ?? ?? ?? ?? ?? 03 c3 50 e8 ?? ?? ?? ?? 01 ?? ?? 8b ?? ?? 8b ?? ?? 83 c4 0c e8 ?? ?? ?? ?? 83 e8 00 74 ?? 48 75 ?? 6a 00 57 ff ?? ?? ?? ?? ?? ff ?? ?? ff ?? ?? ?? ?? ?? 8b f0 85 f6 75 ?? 8b ?? ?? 8b ?? ?? e8 ?? ?? ?? ?? f7 d8 1b c0 40 eb ?? 48 32 c0 eb ?? b0 01 5f 5e 5b c9 c3}
	condition:
		any of ($hex*)
}

rule TrojanDownloaderWin32PerkeshSamle
{
	meta:
		Description  = "Trojan.Perkesh.rc"
		ThreatLevel  = "5"
	strings:
		$a = "698d51" ascii wide
		$b = "%s~%x.dat" ascii wide
		$c = "\\drivers\\etc\\hosts" ascii wide
	condition:
		all of them
}

rule TrojanDownloaderWin32PerkeshDriverSamle
{
	meta:
		Description  = "Trojan.Perkesh.rc"
		ThreatLevel  = "5"
	strings:
		$a = "C:\\FOUND.001\\333888\\sys\\Driver\\i386\\feiji.pdb" ascii wide
	condition:
		$a
}
import"pe"
rule TrojanDropperMicrojoin
{
	meta:
		Description  = "Trojan.Microjoin.rc"
		ThreatLevel  = "5"

	strings:
		$ep = { 55 8B EC 6A FF 68 00 00 00 00 68 00 00 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 5F 5E 5B 33 C0 83 C4 78 5D }

	condition:
		$ep at pe.entry_point
}rule TrojanDownloaderWin32Frethog_E_Sample
{
 	meta:
 		Description  = "Trojan.Frethog.sm"
 		ThreatLevel  = "5"

 	strings:
 		$ = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" ascii wide
		$ = "DownLoad File:" ascii wide
		$ = "\\system32\\mswinsck.ocx" ascii wide

		$ = "http://www.pc918.net/file.txt" ascii wide
		$ = "http://www.yswm.net/file.txt" ascii wide
		$ = "http://www.v138.net/file.txt" ascii wide
		$ = "http://www.v345.net/file.txt" ascii wide
		$ = "http://www.ahwm.net/file.txt" ascii wide
		$ = "http://user.yswm.net/yswm" ascii wide

		$ = "so118config" ascii wide
		$ = "http://user.yswm.net" ascii wide
		$ = "hide.exe" ascii wide
		$ = "\\win.ini" ascii wide
		$ = "\\system32\\svchost.exe" ascii wide
		$ = "P2P DownFile:" ascii wide
		$ = "yswm.runsoft" ascii wide
		$ = "\\sys.dat" ascii wide

 	condition:
 		4 of them
}rule TrojanGBotSampleA_Malex
{
	meta:
		Description  = "Trojan.GBot.sm"
		ThreatLevel  = "5"

	strings:
		$ = "My name is \"G-Bot\" or \"GBot\"!"ascii wide
		$ = "C:\\WINDOWS\\WinUpdaterstd\\svchost.exe"ascii wide
		$hex0 = { 85 d2 74 ?? 8b ?? ?? 41 7f ?? 50 52 8b ?? ?? e8 ?? ?? ?? ?? 89 c2 58 52 8b ?? ?? e8 ?? ?? ?? ?? 5a 58 eb ?? f0 ?? ?? ?? 87 ?? 85 d2 74 ?? 8b ?? ?? 49 7c ?? f0 ?? ?? ?? 75 ?? 8d ?? ?? e8 ?? ?? ?? ?? c3}
		$hex1 = { 53 56 8b f2 8b d8 66 ?? ?? ?? 66 3d b0 d7 72 ?? 66 3d b3 d7 76 ?? bb 66 00 00 00 eb ?? 66 3d b0 d7 74 ?? 8b c3 e8 ?? ?? ?? ?? 66 ?? ?? ?? 80 ?? ?? ?? 75 ?? 83 ?? ?? ?? 75 ?? c7 ?? ?? ?? ?? ?? ?? 8b c3 ff ?? ?? 8b d8 85 db 74 ?? 8b c3 e8 ?? ?? ?? ?? 8b c3 5e 5b c3}

	condition:
		any of them
}rule TrojanDropperWin32Gamarue_A_Andromeda
{
 	meta:
 		Description  = "Trojan.Andromeda.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = { 66 8B 10 66 3B 11 75 1E 66 3B D3 74 15 66 8B 50 02 66 3B 51 02 75 0F 83 C0 04 83 C1 04 66 3B D3 75 DE 33 C0 EB 05 1B C0 83 D8 FF 3B C3 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? ?? 56 FF D7 85 C0 75 ?? }
		$a = "ldr\\CUSTOM\\local\\local\\Release\\ADropper.pdb" ascii wide
		$ = "EpisodeNorth.exe" ascii wide
		$ = "HandballChampionship.exe" ascii wide
		$ = "\\#MSI" ascii wide
		$ = "\\MSI" ascii wide
		$ = "\\msiexec.exe" ascii wide
		$ = "avp.exe" ascii wide
		$ = "\\(empty).lnk" ascii wide
		$b = "hsk\\ehs\\dihviceh\\serhlsethntrohntcohurrehem\\chsyst" ascii wide

 	condition:
 		(3 of them) or $a or $b
}
rule TrojanInjectorA
{
   meta:
       Description = "Trojan.Injector.vb"
       ThreatLevel = "5"

   strings:
		$ = "KERNEO32.nll"  ascii wide
		$ = "CfeateFileAaocwwA"  ascii wide
		$ = "RGPdFileREjhsoX"  ascii wide

   condition:
      all of them
}
rule TrojanWin32KovterSample
{
	meta:
		Description  = "Trojan.Kovter.sm"
		ThreatLevel  = "5"

	strings:
		$ = "AntiVirtualBox" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
		$ = "AntiVMware" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
		$ = "AntiVMwareEx" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
		$ = "AntiVirtualPC" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
		$ = "AntiSandboxie" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
		$ = "AntiThreadExpert" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              
		$ = "AntiWireshark" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
		$ = "AntiJoeBox" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
		$ = "AntiRFP" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
		$ = "AntiAllDebugger" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
		$ = "AntiODBG" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
		$ = "AntiSoftIce" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
		$ = "AntiSyserDebugger" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
		$ = "AntiTrwDebugger" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
		$ = "AntiVirtualMachine" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
		$ = "AntiSunbeltSandboxie" ascii wide                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
	
		$a = "i:\\MySoft\\project Locker\\optimize orig Binary\\kol\\err.pas" ascii wide

	condition:
		3 of them or $a
}rule TrojanDownloaderWin32KuluozSampleB
{
	meta:
		Description  = "Trojan.Asprox.sm"
		ThreatLevel  = "5"
	strings:
		$ = "svchost.exe" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "/index.php?r=gate&id=" ascii wide
		$ = "/index.php?r=gate/getipslist&id=" ascii wide
		$ = "You fag" ascii wide
		$ = "For group" ascii wide
		$hex0 = { 55 8b ec 81 ec dc 00 00 00 90 68 1c 10 40 00 ff ?? ?? ?? ?? ?? 89 ?? ?? 68 28 10 40 00 8b ?? ?? 50 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 68 44 10 40 00 8b ?? ?? 51 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 68 58 10 40 00 8b ?? ?? 52 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 68 6c 10 40 00 8b ?? ?? 50 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 68 7c 10 40 00 8b ?? ?? 51 ff ?? ?? ?? ?? ?? 89 ?? ?? 68 94 10 40 00 8b ?? ?? 52 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? b8 50 89 40 00 2d b0 10 40 00 89 ?? ?? c7 ?? ?? ?? ?? ?? ?? eb ?? 8b ?? ?? 83 c1 01 89 ?? ?? 83 ?? ?? ?? 73 ?? 8b ?? ?? c6 ?? ?? ?? ?? ?? ?? ?? eb ?? c7 ?? ?? ?? ?? ?? ?? eb ?? 8b ?? ?? 83 c0 01 89 ?? ?? 83 ?? ?? ?? 73 ?? 8b ?? ?? c6 ?? ?? ?? ?? eb ?? c7 ?? ?? ?? ?? ?? ?? 90 8d ?? ?? ?? ?? ?? 52 8d ?? ?? 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 68 a4 10 40 00 6a 00 ff ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 6a 00 6a 18 8d ?? ?? 50 6a 00 8b ?? ?? ?? ?? ?? 51 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? 83 c2 08 89 ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 6a 04 8d ?? ?? ?? ?? ?? 51 8b ?? ?? ?? ?? ?? 52 8b ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 00 68 00 00 00 08 6a 40 8d ?? ?? ?? ?? ?? 52 6a 00 68 1f 00 0f 00 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? 6a 40 6a 00 6a 01 8d ?? ?? ?? ?? ?? 52 6a 00 6a 00 6a 00 8d ?? ?? ?? ?? ?? 50 6a ff 8b ?? ?? 51 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? eb ?? 8b ?? ?? 83 c2 01 89 ?? ?? 8b ?? ?? 3b ?? ?? 73 ?? b9 b0 10 40 00 03 ?? ?? 8b ?? ?? ?? ?? ?? 03 ?? ?? 8a ?? 88 ?? eb ?? 90 c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 40 6a 00 6a 01 8d ?? ?? ?? ?? ?? 51 6a 00 6a 00 6a 00 8d ?? ?? ?? ?? ?? 52 8b ?? ?? ?? ?? ?? 50 8b ?? ?? 51 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? 6a 40 68 00 30 00 00 68 00 00 50 00 6a 00 ff ?? ?? ?? ?? ?? 89 ?? ?? 8d ?? ?? ?? ?? ?? 50 68 00 10 00 00 8b ?? ?? 51 8b ?? ?? ?? ?? ?? 52 8b ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? 8b ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 51 8b ?? ?? 52 8b ?? ?? 50 8b ?? ?? ?? ?? ?? 51 8b ?? ?? ?? ?? ?? 52 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 00 68 00 00 00 08 6a 40 8d ?? ?? ?? ?? ?? 51 6a 00 68 1f 00 0f 00 8d ?? ?? ?? ?? ?? 52 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 40 6a 00 6a 01 8d ?? ?? ?? ?? ?? 51 6a 00 6a 00 6a 00 8d ?? ?? ?? ?? ?? 52 6a ff 8b ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? 03 ?? ?? ?? ?? ?? c6 ?? ?? 8b ?? ?? 03 ?? ?? ?? ?? ?? c6 ?? ?? ?? 8b ?? ?? 03 ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? 8b ?? ?? 03 ?? ?? ?? ?? ?? c6 ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? eb ?? 8b ?? ?? 83 c0 01 89 ?? ?? 8b ?? ?? 3b ?? ?? 73 ?? 8b ?? ?? ?? ?? ?? 03 ?? ?? 8b ?? ?? 03 ?? ?? 8a ?? 88 ?? eb ?? 90 8b ?? ?? ?? ?? ?? 52 8b ?? ?? ?? ?? ?? 50 ff ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 6a 40 6a 00 6a 01 8d ?? ?? ?? ?? ?? 50 6a 00 6a 00 6a 00 8d ?? ?? ?? ?? ?? 51 8b ?? ?? ?? ?? ?? 52 8b ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 6a 00 8b ?? ?? ?? ?? ?? 51 ff ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 68 e8 03 00 00 ff ?? ?? ?? ?? ?? 6a 00 ff ?? ?? ?? ?? ?? 8b e5 5d c3}
	condition:
		(3 of them) or $hex0
}rule TrojanWin32LethicBSample
{
	meta:
		Description  = "Trojan.Lethic.sm"
		ThreatLevel  = "5"
	strings:
		$ = "zaproxza" ascii wide
		$ = "93.190.137.51" ascii wide
		$ = "antaw" ascii wide
		$hex0 = { e8 ?? ?? ?? ?? 8b ?? ?? 52 e8 ?? ?? ?? ?? 8b ?? ?? 50 e8 ?? ?? ?? ?? 68 74 43 40 00 e8 ?? ?? ?? ?? 89 ?? ?? 6a 33 68 00 40 40 00 8b ?? ?? 51 e8 ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? 83 ?? ?? ?? ?? ?? ?? 75 ?? e9 ?? ?? ?? ?? 8b ?? ??}
	condition:
		(2 of them) or (any of ($hex*))
}rule TrojanWin32NecursSample
{
 	meta:
 		Description  = "Trojan.Necurs.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = "some stupid error %u" ascii wide
		$ = "loading" ascii wide
		$ = "unloading" ascii wide
		$ = "exception %08x %swhen %s at %p" ascii wide
		$ = "microsoft.com" ascii wide
		$ = "facebook.com" ascii wide
		$a = "NitrGB" ascii wide
		$ = "\\Installer\\{" ascii wide
		$ = "%s%0.8X-%0.4X-%0.4X-%0.4X-%0.8X%0.4X}\\" ascii wide
		$ = "syshost32" ascii wide
		$ = "%s\\svchost.exe" ascii wide

 	condition:
 		(8 of them) or $a
}

rule TrojanWinNTNecursSample
{
 	meta:
 		Description  = "Trojan.Necurs.sm"
 		ThreatLevel  = "5"

 	strings:
		$a = "F:\\cut\\abler\\detecting\\overlapping\\am.pdb" ascii wide
		$ = "VirusBuster Ltd" ascii wide
		$ = "Beijing Jiangmin" ascii wide
		$ = "SUNBELT SOFTWARE" ascii wide
		$ = "Sunbelt Software" ascii wide
		$ = "K7 Computing" ascii wide
		$ = "Immunet Corporation" ascii wide
		$ = "Beijing Rising" ascii wide
		$ = "G DATA Software" ascii wide
		$ = "Quick Heal Technologies" ascii wide
		$ = "Comodo Security Solutions" ascii wide
		$ = "CJSC Returnil Software" ascii wide
		$ = "NovaShield Inc" ascii wide
		$ = "BullGuard Ltd" ascii wide
		$ = "Check Point Software Technologies Ltd" ascii wide
		$ = "Panda Software International" ascii wide
		$ = "Kaspersky Lab" ascii wide
		$ = "FRISK Software International Ltd" ascii wide
		$ = "ESET, spol. s r.o." ascii wide
		$ = "Doctor Web Ltd" ascii wide
		$ = "BitDefender SRL" ascii wide
		$ = "BITDEFENDER LLC" ascii wide
		$ = "Avira GmbH" ascii wide
		$ = "GRISOFT, s.r.o." ascii wide
		$ = "PC Tools" ascii wide
		$ = "ALWIL Software" ascii wide
		$ = "Agnitum Ltd" ascii wide

 	condition:
 		(8 of them) or $a
}rule TrojanWin32NedsymGSample
{
	meta:
		Description  = "Trojan.Nedsym.sm"
		ThreatLevel  = "5"

	strings:
		$ = "qwertyuiopasdfghjklzxcvbnm123456789"  ascii wide
		$ = "svcnost.exe"  ascii wide
		$ = "Windows Init"  ascii wide
		$ = "\\drivers\\etc\\hosts"  ascii wide

	condition:
		2 of them
}rule TrojanWin32NeurevtA_BackDoor
{
	meta:
		Description  = "Trojan.Neurevt.sm"
		ThreatLevel  = "5"

	strings:
		$ = "%s\\__%08x.lnk" ascii wide
		$ = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s" ascii wide
		$ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
		$ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "{2227A280-3AEA-1069-A2DE-08002B30309D}" ascii wide
		$ = "schtasks.exe" ascii wide
		$ = "SYSTEM\\CurrentControlSet\\Control\\Session Manager" ascii wide
		$ = "Software\\Classes\\CLSID\\%s\\%08X\\%s" ascii wide
		$ = "%s\\%08X.pif" ascii wide
		$ = "Windows ha detectado una carpeta da" ascii wide
		$ = "Mostrar Detalles" ascii wide
		$ = "Mas informaci" ascii wide
		$ = "Restaurar archivos" ascii wide
		$ = "Restaurar archivos y chequear el disco en busca de errores" ascii wide
		$ = "Erro de Disco Cr" ascii wide
		$ = "O Windows encontrou uma pasta corrompida no seu disco r" ascii wide
		$ = "Mostrar detalhes" ascii wide
		$ = "Mais detalhes sobre esse erro" ascii wide
		$ = "Restaurar os arquivos" ascii wide
		$ = "Restaurar os arquivos e verificar erros no disco" ascii wide
		$ = "Kritischer Festplattenfehler" ascii wide
		$ = "Windows hat einen fehlerhaften Ordner auf deiner Festplatte vorgefunden." ascii wide
		$ = "Mehrere fehlerhafte Dateien wurden in dem Ordner 'Eigene Dokumente' gefunden. Um Datenverlust zu ver" ascii wide
		$ = "Details anzeigen" ascii wide
		$ = "Mehr Details zu diesem Fehler" ascii wide
		$ = "Dateien wiederherstellen" ascii wide
		$ = "Dateien wiederherstellen und Festplatte auf Fehler " ascii wide
		$ = "Erreur Critique" ascii wide
		$ = "Windows a trouv" ascii wide
		$ = "Plusieurs fichiers corrompu sont trouv" ascii wide
		$ = "Montre d" ascii wide
		$ = "Plus de d" ascii wide
		$ = "Kritieke foutmelding" ascii wide
		$ = "Windows heeft een beschadigde map gevonden" ascii wide
		$ = "Meerdere beschadigde bestanden zijn in de map 'Mijn Documenten' gevonden. Om dataverlies te voorkome" ascii wide
		$ = "Toon details" ascii wide
		$ = "Meer details over deze foutmelding" ascii wide
		$ = "Herstel bestanden" ascii wide
		$ = "Herstel bestanden en controleer de harde schijf voor errors" ascii wide
		$ = "Kritik disk hatas" ascii wide
		$ = "Windows sabit diskinizde bozuk bir klas" ascii wide
		$ = "Bu hata hakk" ascii wide
		$ = "Dosyalar" ascii wide
		$ = "Hata ayr" ascii wide
		$ = "Kritis Disk Kesalahan" ascii wide
		$ = "Windows telah mengalami rusak folder pada hard drive Anda" ascii wide
		$ = "Beberapa file rusak telah ditemukan di folder 'My Documents'. Untuk mencegah kerugian serius data, p" ascii wide
		$ = "Tampilkan detail" ascii wide
		$ = "Lebih rinci tentang kesalahan ini" ascii wide
		$ = "mengembalikan file" ascii wide
		$ = "Kembalikan file dan memeriksa disk untuk kesalahan" ascii wide
		$ = "Errore critico dell'hard disk" ascii wide
		$ = "Windows ha trovato una cartella corrotta nel vostro hard disk." ascii wide
		$ = "Mostra dettagli" ascii wide
		$ = "Maggiori dettagli su quest'errore" ascii wide
		$ = "Ripristina i file" ascii wide
		$ = "Ripristina i file e controlla il disco per errori." ascii wide
		$ = "Kriittinen Levy Virhe" ascii wide
		$ = "Windows on t" ascii wide
		$ = "Useita korruptoituneita tiedostoja on l" ascii wide
		$ = "Palauta tiedostot" ascii wide
		$ = "Palauta tiedostot ja etsi virheit" ascii wide
		$ = "Problem, krytyczny stan dysku" ascii wide
		$ = "Windows znalazl korupcyjny folder w twoim twardym dysku." ascii wide
		$ = "Duza ilosc zepsutych plikow zostala znaleziona w swoim folderze 'My Documents'. Zeby zachowac pamiec" ascii wide
		$ = "Pokaz wiecej informacji" ascii wide
		$ = "Wiecej danych na temat bledu" ascii wide
		$ = "Przywracanie plik" ascii wide
		$ = "Critical Disk Error" ascii wide
		$ = "Windows has encountered a corrupted folder on your hard drive" ascii wide
		$ = "Multiple corrupted files have been found in the folder 'My Documents'. To prevent serious loss of da" ascii wide
		$ = "Show details" ascii wide
		$ = "More details about this error" ascii wide
		$ = "Restore files and check disk for errors" ascii wide
		$ = "http://answers.microsoft.com/en-us/windows/forum/windows_vista-windows_programs/corrupted-documents-folder/e2a7660f-8eea-4f27-b2e6-e77a0f0c1535" ascii wide
		$ = "uac" ascii wide
		$ = "nuac" ascii wide
		$ = "Has denegado los privilegios de Windows para la utilidad de restauraci" ascii wide
		$ = "Error en los privilegios" ascii wide
		$ = "Erro de privil" ascii wide
		$ = "Sie verweigerten Windows die Privilegien, das Dateiwiederherstellungswerkzeug zu nutzen. Bitte w" ascii wide
		$ = "Privilegfehler" ascii wide
		$ = "Vous avez rejet" ascii wide
		$ = "Erreur de privil" ascii wide
		$ = "U heeft de nodige rechten afgewezen voor de Windows herstelprocedure. Selecteer JA op de volgende UA" ascii wide
		$ = "Toestemming error" ascii wide
		$ = "Windows dosya restorasyon program" ascii wide
		$ = "Izin hatas" ascii wide
		$ = "Anda menyangkal hak-hak istimewa yang tepat untuk utilitas restorasi file Windows. Silakan pilih YES" ascii wide
		$ = "Privilege Kesalahan" ascii wide
		$ = "Hai negato i privilegi necessari a Windows per riparare i file. Selezione \"Si\" nella seguente finest" ascii wide
		$ = "Errore nei privilegi" ascii wide
		$ = "Et sallinut oikeuksia Windowsin tiedostojen palautus ohjelmistolle. Ole hyv" ascii wide
		$ = "Windows file restoration utility" ascii wide
		$ = "You denied the proper privileges to the Windows file restoration utility. Please select YES on the f" ascii wide
		$ = "Privilege Error" ascii wide
		$ = "local ip detected" ascii wide

		$hex0 = { 55 8b ec 81 ec 04 01 00 00 83 ?? ?? ?? 56 57 0f ?? ?? ?? ?? ?? 8b ?? ?? e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? be 34 71 42 00 8b ce e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 81 c2 ae 17 00 00 8b ca e8 ?? ?? ?? ?? 83 f8 08 0f ?? ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 8b f8 85 ff 74 ?? 68 04 01 00 00 6a 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 56 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 57 68 68 a3 42 00 50 ff ?? ?? ?? ?? ?? 83 c4 14 57 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 d2 04 00 00 ff ?? ?? ?? ?? ?? 8b f0 ff ?? ?? ?? ?? ?? ff ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b f8 83 fe 01 75 ?? 6a 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8b c7 eb ?? 33 c0 5f 5e c9 c2 04 00 55}
		$hex1 = { 55 8b ec 81 ec 04 01 00 00 53 33 db 57 39 ?? ?? 0f ?? ?? ?? ?? ?? 8b ?? ?? 3b cb 0f ?? ?? ?? ?? ?? 39 ?? ?? 0f ?? ?? ?? ?? ?? 3b f3 0f ?? ?? ?? ?? ?? 39 ?? 0f ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b ?? ?? e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 81 c2 ae 17 00 00 8b ca e8 ?? ?? ?? ?? 83 f8 08 0f ?? ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 8b f8 3b fb 0f ?? ?? ?? ?? ?? 68 04 01 00 00 53 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff ?? ?? a1 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 57 68 68 a3 42 00 50 ff ?? ?? ?? ?? ?? 83 c4 14 57 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 d2 04 00 00 ff ?? ?? ?? ?? ?? 8b f8 ff ?? ?? ?? ?? ?? ff ?? ?? 8b ?? ff ?? ?? 8d ?? ?? ?? ?? ?? 50 68 01 00 00 80 e8 ?? ?? ?? ?? 89 ?? 83 ff 01 75 ?? 53 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 39 ?? 0f 95 c0 eb ?? 32 c0 5f 5b c9 c2 0c 00}
		$hex2 = { 55 8b ec 81 ec 98 06 00 00 8b cf e8 ?? ?? ?? ?? 83 f8 01 73 ?? 33 c0 40 c9 c3 53 56 57 32 db ff ?? ?? ?? ?? ?? 68 08 02 00 00 8b f0 6a 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 68 03 01 00 00 57 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 f2 14 00 00 50 56 ff ?? ?? ?? ?? ?? 85 c0 74 ?? a1 ?? ?? ?? ?? 05 f2 14 00 00 50 8b d7 e8 ?? ?? ?? ?? 85 c0 78 ?? 33 c0 40 e9 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? be 80 00 00 00 eb ?? ff ?? ?? ?? ?? ?? 83 f8 05 75 ?? 84 db 75 ?? 8b cf e8 ?? ?? ?? ?? 83 f8 01 72 ?? 57 e8 ?? ?? ?? ?? b3 01 56 57 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 57 ff ?? ?? ?? ?? ?? 8b f0 85 f6 74 ?? 68 00 c1 42 00 56 ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 68 0c c1 42 00 56 ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 6a 5c 5e 8b d7 e8 ?? ?? ?? ?? 40 50 57 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 50 8d ?? ?? ?? ?? ?? 50 8d ?? ?? ?? ?? ?? 68 18 c1 42 00 50 ff ?? ?? ?? ?? ?? 83 c4 10 6a 08 8d ?? ?? ?? ?? ?? 50 57 ff ?? ?? ?? ?? ?? 85 c0 75 ?? 6a 04 50 57 ff ?? ?? ?? ?? ?? 57 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 85 c0 75 ?? 68 8c 00 00 00 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 83 f8 05 75 ?? 8b cf e8 ?? ?? ?? ?? 83 f8 01 72 ?? 57 e8 ?? ?? ?? ?? eb ?? 32 c0 fe c8 0f b6 c0 f7 d8 1b c0 83 e0 02 eb ?? 6a 03 58 eb ?? 33 c0 5e 5b c9 c3}
		$hex3 = { 55 8b ec 83 e4 f8 51 8b ?? ?? 57 85 d2 0f ?? ?? ?? ?? ?? 0f ?? ?? 66 85 c9 0f ?? ?? ?? ?? ?? 0f ?? ?? ?? 83 e8 00 0f ?? ?? ?? ?? ?? 48 74 ?? 48 0f ?? ?? ?? ?? ?? 48 0f ?? ?? ?? ?? ?? b8 1c 03 00 00 66 3b c8 0f ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f ?? ?? ?? 50 e8 ?? ?? ?? ?? 3c 01 0f ?? ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? b8 18 01 00 00 66 3b c8 75 ?? a1 ?? ?? ?? ?? 83 ?? ?? ?? 74 ?? 8d ?? ?? 8b cf e8 ?? ?? ?? ?? 83 f8 02 76 ?? 8b ?? ?? f6 c2 01 74 ?? e8 ?? ?? ?? ?? 83 f8 fe 75 ?? a1 ?? ?? ?? ?? 03 c0 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? eb ?? f6 c2 02 74 ?? 57 e8 ?? ?? ?? ?? eb ?? f6 c2 04 74 ?? e8 ?? ?? ?? ?? eb ?? b8 24 14 00 00 66 3b c8 75 ?? a1 ?? ?? ?? ?? 0f ?? ?? ?? 50 e8 ?? ?? ?? ?? 3c 01 75 ?? 8b c2 e8 ?? ?? ?? ?? 33 c0 40 eb ?? 33 c0 5f 8b e5 5d c2 04 00}
		$hex4 = { 8b ?? ?? c6 ?? ?? ?? ?? ff ?? ?? 83 f9 37 8b ?? ?? 7e ?? eb ?? c6 ?? ?? ?? ?? ff ?? ?? 8b ?? ?? 83 f9 40 7c ?? e8 ?? ?? ?? ?? eb ?? 8b ?? ?? c6 ?? ?? ?? ?? ff ?? ?? 83 ?? ?? ?? 7c ?? eb ?? c6 ?? ?? ?? ?? ff ?? ?? 8b ?? ?? 83 f9 38 7c ?? 8a ?? ?? 88 ?? ?? 8a ?? ?? 88 ?? ?? 8a ?? ?? 88 ?? ?? 8a ?? ?? 88 ?? ?? 8a ?? ?? 88 ?? ?? 8a ?? ?? 88 ?? ?? 8a ?? ?? 88 ?? ?? 8a ?? ?? 88 ?? ?? e9 ?? ?? ?? ??}
		$hex5 = { 55 8b ec 51 51 56 33 f6 57 8b f9 3b c6 74 ?? 39 ?? ?? 74 ?? 3b fe 74 ?? 39 ?? ?? 74 ?? 6a 07 5a 39 ?? ?? 72 ?? 89 ?? ?? 89 ?? ?? 39 ?? ?? 76 ?? 53 eb ?? 33 f6 3b ?? ?? 77 ?? 8b ?? ?? 8d ?? ?? ?? 8a ?? ?? 3a ?? ?? 75 ?? ff ?? ?? 83 ?? ?? ?? 75 ?? 8d ?? ?? eb ?? 8a ?? ?? 88 ?? ?? 41 3b ca 72 ?? ff ?? ?? 46 83 fe 07 72 ?? eb ?? 83 ?? ?? ?? 42 8d ?? ?? 4f 3b ?? ?? 72 ?? 5b 8b ?? ?? eb ?? 83 c8 ff 5f 5e c9 c2 08 00}


	condition:
		(10 of them) or (any of ($hex*))
}rule MalwarePowerLoaderSample
{
	meta:
		Description  = "Trojan.PowerLoader.sm"
		ThreatLevel  = "5"

	strings:
		$str_1 = "powerloader" ascii wide

		$ = "inject64_section" ascii wide
		$ = "inject64_event" ascii wide
		$ = "inject_section" ascii wide
		$ = "inject_event" ascii wide
		$ = "loader.dat" ascii wide
		$ = "Inject64End" ascii wide
		$ = "Inject64Normal" ascii wide
		$ = "Inject64Start" ascii wide
		$ = "UacInject64End" ascii wide
		$ = "UacInject64Start" ascii wide
	condition:
		(2 of them) or (any of ($str_*))
}rule TrojanRansomRevetonSample
{
	meta:
		Description  = "Trojan.Reveton.sm"
		ThreatLevel  = "5"

	strings:
		$a = "JimmMonsterNew" ascii wide
		$  = "regedit.exe" ascii wide
		$  = "rundll32.exe" ascii wide
		$  = "msconfig.lnk" ascii wide
		$  = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide
		$  = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide
		$  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ctfmon.exe" ascii wide
	condition:
		(3 of them) or $a
}

rule TrojanWin32UrausySampleA
{
	meta:
		Description  = "Trojan.Urausy.sm"
		ThreatLevel  = "5"

	strings:
		$a = { 55 89 E5 53 56 57 83 0D ?? ?? ?? ?? 01 31 C0 5F 5E 5B C9 C2 04 00 }
		$b = { FF 15 ?? ?? ?? ?? 09 C0 0F 84 ?? ?? ?? ?? 8B 75 ?? 89 C3 6A 01 6A FF 6A 05 56 E8 }

	condition:
		$a and $b
}

rule TrojanRansomWin32TobfySample
{
 	meta:
 		Description  = "Trojan.Tobfy.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = "http://62.109.28.231/gtx3d16bv3/upload/img.jpg" ascii wide
		$ = "http://62.109.28.231/gtx3d16bv3/upload/mp3.mp3" ascii wide

		$ = "Pay MoneyPak" ascii wide
		$ = "You have 72 hours to pay the fine!" ascii wide
		$ = "Wait! Your request is processed within 24 hours." ascii wide
		$a = "G:\\WORK\\WORK_PECEPB\\Work_2012 Private\\Project L-0-ck_ER\\NEW Extern\\inject\\injc\\Release\\injc.pdb" ascii wide
		$b = "G:\\WORK\\WORK_PECEPB\\Work_2012 Private\\Project L-0-ck_ER\\Version V 1.0\\V1.0\\Release\\te.pdb" ascii wide
		$ = "picture.php?pin=" ascii wide
		$ = "s\\sound.mp3" ascii wide
		$ = "s\\1.jpg" ascii wide
		$ = "s\\1.bmp" ascii wide
		$ = "getunlock.php" ascii wide

 	condition:
 		(4 of them) or $a or $b
}rule Regin_APT_KernelDriver_Generic_A {
        meta:
		        Description = "Trojan.Regin.A.sm"
				ThreatLevel = "5"
        strings:
                $m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }

                $s0 = "atapi.sys" fullword wide
                $s1 = "disk.sys" fullword wide
                $s3 = "h.data" fullword ascii
                $s4 = "\\system32" fullword ascii
                $s5 = "\\SystemRoot" fullword ascii
                $s6 = "system" fullword ascii
                $s7 = "temp" fullword ascii
                $s8 = "windows" fullword ascii

                $x1 = "LRich6" fullword ascii
                $x2 = "KeServiceDescriptorTable" fullword ascii
        condition:
                $m1 and all of ($s*) and 1 of ($x*)
}

rule Regin_APT_KernelDriver_Generic_B {
        meta:
				Description = "Trojan.Regin.B.sm"
				ThreatLevel = "5"
        strings:
                $s1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
                $s2 = "H.data" fullword ascii nocase
                $s3 = "INIT" fullword ascii
                $s4 = "ntoskrnl.exe" fullword ascii

                $v1 = "\\system32" fullword ascii
                $v2 = "\\SystemRoot" fullword ascii
                $v3 = "KeServiceDescriptorTable" fullword ascii

                $w1 = "\\system32" fullword ascii
                $w2 = "\\SystemRoot" fullword ascii
                $w3 = "LRich6" fullword ascii

                $x1 = "_snprintf" fullword ascii
                $x2 = "_except_handler3" fullword ascii

                $y1 = "mbstowcs" fullword ascii
                $y2 = "wcstombs" fullword ascii
                $y3 = "KeGetCurrentIrql" fullword ascii

                $z1 = "wcscpy" fullword ascii
                $z2 = "ZwCreateFile" fullword ascii
                $z3 = "ZwQueryInformationFile" fullword ascii
                $z4 = "wcslen" fullword ascii
                $z5 = "atoi" fullword ascii
        condition:
                all of ($s*) and ( all of ($v*) or all of ($w*) or all of ($x*) or all of ($y*) or all of ($z*) )
}

rule Regin_APT_KernelDriver_Generic_C {
        meta:
				Description = "Trojan.Regin.C.sm"
				ThreatLevel = "5"
                /*description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
                author = "@Malwrsignatures - included in APT Scanner THOR"
                date = "23.11.14"
                hash1 = "e0895336617e0b45b312383814ec6783556d7635"
                hash2 = "732298fa025ed48179a3a2555b45be96f7079712"  */
        strings:

                $s0 = "KeGetCurrentIrql" fullword ascii
                $s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
                $s2 = "usbclass" fullword wide

                $x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
                $x2 = "Universal Serial Bus Class Driver" fullword wide
                $x3 = "5.2.3790.0" fullword wide

                $y1 = "LSA Shell" fullword wide
                $y2 = "0Richw" fullword ascii
        condition:
                all of ($s*) and ( all of ($x*) or all of ($y*) )
}

rule Regin_sig_svcsstat {
        meta:
				Description = "Trojan.Regin.sm"
				ThreatLevel = "5"
                /*description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
                author = "@Malwrsignatures"
                date = "25.11.14"
                score = 70
                hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"*/
        strings:
                $s0 = "Service Control Manager" fullword ascii
                $s1 = "_vsnwprintf" fullword ascii
                $s2 = "Root Agency" fullword ascii
                $s3 = "Root Agency0" fullword ascii
                $s4 = "StartServiceCtrlDispatcherA" fullword ascii
                $s5 = "\\\\?\\UNC" fullword ascii
                $s6 = "%ls%ls" fullword wide
        condition:
                all of them and filesize < 15KB and filesize > 10KB
}rule TrojanWin32RovnixSample
{
	meta:
		Description  = "Trojan.Rovnix.sm"
		ThreatLevel  = "5"
	strings:
		$ = "dropper.exe" ascii wide
		$ = "dropper_x64.exe" ascii wide
		$ = "Inject64Start" ascii wide
		$ = "Inject64End" ascii wide
		$ = "Inject64Normal" ascii wide
		$ = "inject_section" ascii wide
		$ = "inject_event" ascii wide
		$ = "0:/plugins/%s" ascii wide
		$ = "0:/plugins/base" ascii wide
		$ = "0:/plugins/base/binary" ascii wide
		$ = "0:/plugins/base/mask" ascii wide
		$ = "0:/plugins/base/version" ascii wide
		$ = "0:/plugins/base/once" ascii wide
		$ = "0:/plugins/rootkit" ascii wide
		$ = "0:/plugins/rootkit/binary" ascii wide
		$ = "0:/plugins/rootkit/version" ascii wide
		$ = "0:/plugins/rootkit/binary" ascii wide
		$ = "0:\\storage\\keylog" ascii wide
		$ = "0:\\storage\\config" ascii wide
		$ = "0:\\storage\\intrnl" ascii wide
		$ = "0:\\storage\\passw" ascii wide
		$ = "0:\\storage\\hunter" ascii wide
		$ = "0:/hidden" ascii wide
		$ = "0:/hidden/%s" ascii wide
		$ = "0:/hidden/%s/path" ascii wide
		$ = "0:/hidden/%s/binary" ascii wide
		$ = "0:/hidden/%s/mask" ascii wide
	condition:
		3 of them
}rule TrojanDroppedBackdoorWin32SimdaSample
{
	meta:
		Description  = "Trojan.Simda.sm"
		ThreatLevel  = "5"

	strings:
		$ = ".driver" ascii wide
		$ = ".userm"  ascii wide
		$ = ".uac64"  ascii wide
		$ = ".mcp"    ascii wide
		$ = ".cfgbin" ascii wide
		$ = ".uacdll" ascii wide
		$ = "%s\\%s.sys" ascii wide
		$ = "%s\\%s.exe" ascii wide
		$ = "%appdata%\\ScanDisc.exe" ascii wide
	condition:
		4 of them
}// Rule - Dropped file from Trojan Sirefef / ZeroAccess.
rule TrojanSirefefZerroAccess
{
	meta:
		Description  = "Trojan.Sirefef.sm"
		ThreatLevel  = "5"

	strings:

		//$ = "n64" ascii wide
		//$ = "n32" ascii wide
		//$ = "$Recycle.Bin\\" ascii wide
		$ = "\\$%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x" ascii wide
		//$ = "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}"  ascii wide
		
		
		$ = "%wZ\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" ascii wide 
		$ = "%wZ\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"  ascii wide
		$ = "%wZ\\Software\\Classes\\clsid" ascii wide		
		$ = "\\registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" ascii wide 
		$ = "\\registry\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide    
				
		$ = "\\systemroot\\system32\\config" ascii wide  
		$ = "\\??\\ACPI#PNP0303#2&da1a3ff&0" ascii wide   
		$ = "GoogleUpdate.exe" ascii wide
		$ = "Google Update Service (gupdate)" ascii wide
		$ = "%sU\\%08x.@" ascii wide
		$ = "\\??\\%sU" ascii wide
		$ = "\\??\\%s@" ascii wide
		$ = "%08x.@" ascii wide
		$ = "%08x.$" ascii wide
		$ = "%08x.~" ascii wide
		$ = "\\??\\%08x" ascii wide 
		$ = "\\n." ascii wide
		$ = "wbem\\fastprox.dll" ascii wide

		$ = "c:\\windows\\system32\\z" ascii wide
		$s1 = "e:\\sz\\x64\\release\\InCSRSS.pdb"  ascii wide

		$s2 = "C:\\Jinket\\Lownza\\Kueshmmba\\de.pdb" ascii wide
		$s3 = "E:\\Marlne\\Bensjo\\Ernstedun\\Rugriayid\\Wasp851.pdb" ascii wide

		$hex0 = { 55 8b ec 83 ec 48 53 56 57 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8d ?? ?? ?? 59 8b c6 e8 ?? ?? ?? ?? 8b c6 89 ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? ff ?? ?? ?? ?? ?? 68 08 54 30 6a ff ?? ?? ff d6 ff ?? ?? ?? ?? ?? 68 18 54 30 6a ff ?? ?? ff d6 83 c4 18 83 ?? ?? ?? ?? ?? ?? 75 ?? 8b ?? ?? ?? ?? ?? bb 98 70 30 6a bf 00 00 10 00 eb ?? ff ?? ?? ff ?? ?? ?? ?? ?? 68 a0 0f 00 00 ff ?? ?? ?? ?? ?? 53 57 8d ?? ?? 50 ff d6 85 c0 7d ?? 68 60 ea 00 00 ff ?? ?? ?? ?? ?? bb 54 70 30 6a eb ?? ff ?? ?? ff ?? ?? ?? ?? ?? 6a 01 68 e0 93 04 00 ff ?? ?? ?? ?? ?? ff ?? ?? e8 ?? ?? ?? ?? 53 57 8d ?? ?? 50 ff d6 85 c0 7d ?? bf 20 71 30 6a 57 ff ?? ?? ?? ?? ?? 6a 00 ff ?? ?? 8d ?? ?? e8 ?? ?? ?? ?? 50 6a 00 ff ?? ?? 8d ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 57 ff ?? ?? ?? ?? ?? 33 c0 8d ?? ?? 5f 5e 5b c9 c2 04 00}
		$hex1 = { 55 8b ec 83 ec 18 56 57 8d ?? ?? 50 e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? be 00 08 00 00 8b c6 e8 ?? ?? ?? ?? 8b fc 33 c0 b9 30 00 fe 7f 66 ?? ?? ?? 66 ?? ?? ?? 89 ?? ?? 0f ?? ?? 0f ?? ?? ?? 8b ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? 41 41 66 83 f8 5c 75 ?? 66 ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? b8 28 55 30 6a 72 ?? b8 3c 55 30 6a 50 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? 0f b7 c8 01 ?? ?? 33 c0 50 66 ?? ?? ?? 8b ?? ?? ff ?? 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 0f ?? ?? ?? 0f ?? ?? ?? 2b c8 83 f9 50 0f ?? ?? ?? ?? ?? 0f ?? ?? ?? 51 0f ?? ?? ?? 51 0f ?? ?? ?? 51 0f ?? ?? ?? 51 0f ?? ?? ?? 51 0f ?? ?? ?? 51 0f ?? ?? ?? 51 0f ?? ?? ?? 51 0f ?? ?? ?? 51 0f ?? ?? ?? 51 ff ?? ?? 8b ?? ?? 03 c1 68 58 55 30 6a 50 ff ?? ?? ?? ?? ?? 57 ff ?? ?? ?? ?? ?? 83 c4 38 6a 02 5a 40 33 c9 f7 e2 0f 90 c1 f7 d9 0b c1 50 6a 00 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 85 c0 74 ?? 57 50 ff ?? ?? ?? ?? ?? 59 33 c0 59 40 eb ?? 33 c0 8d ?? ?? 5f 5e c9 c2 04 00}
		$hex2 = { 8b ?? ?? ?? 83 e8 00 74 ?? 48 75 ?? ff ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 ?? e8 ?? ?? ?? ?? 85 c0 74 ?? 6a 00 6a 00 ff ?? ?? ?? 68 62 13 30 6a 68 00 00 08 00 6a 00 ff ?? ?? ?? ?? ?? eb ?? a1 ?? ?? ?? ?? 85 c0 74 ?? 50 ff ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 85 c0 74 ?? 50 ff ?? ?? ?? ?? ?? 33 c0 40 c2 0c 00}
		$hex3 = { 55 8b ec 51 51 53 56 8b ?? ?? 56 ff ?? ?? ?? ?? ?? 8b d8 85 db 0f ?? ?? ?? ?? ?? 57 6a 40 68 00 10 00 00 ff ?? ?? 6a 00 ff ?? ?? ?? ?? ?? 8b f8 89 ?? ?? 85 ff 0f ?? ?? ?? ?? ?? 8b ?? ?? f3 ?? 0f ?? ?? ?? 0f ?? ?? ?? 8d ?? ?? ?? 83 c0 0c 8b ?? 8b ?? ?? 8b ?? ?? 03 f1 03 f9 8b ?? ?? 83 c0 28 4a f3 ?? 75 ?? 8b ?? ?? 8b ?? ?? ?? ?? ?? 2b ?? ?? 8d ?? ?? 50 6a 05 6a 01 ff ?? ?? ff d7 85 c0 74 ?? eb ?? 8b ?? ?? 29 ?? ?? 56 8d ?? ?? 8b ?? 03 ?? ?? 83 c1 f8 52 d1 e9 51 50 ff ?? ?? ?? ?? ?? 83 ?? ?? ?? 75 ?? 8d ?? ?? 50 6a 01 6a 01 ff ?? ?? ff d7 85 c0 74 ?? 8d ?? ?? 8b ?? 85 c0 74 ?? 8b f1 8b ?? ?? 03 c1 50 ff ?? ?? ?? ?? ?? 83 c6 14 8b ?? 85 c0 75 ?? 8b ?? ?? 5f 5e 5b c9 c2 04 00}
		$hex4 = { 8b ?? ?? ?? ?? ?? b8 00 20 00 00 66 ?? ?? ?? ?? ?? ?? 75 ?? e8 ?? ?? ?? ?? 8b ?? ?? ?? 48 75 ?? 56 ff ?? ?? ?? ff ?? ?? ?? ?? ?? 33 f6 56 6a 04 56 68 0a 1d 40 00 56 56 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 3b c6 74 ?? 56 50 ff ?? ?? ?? ?? ?? 5e b0 01 c2 0c 00}
        $hex5 = { 55 8b ec 83 e4 f8 83 ec 34 53 56 57 33 db 53 6a 18 8d ?? ?? ?? 50 53 ff ?? ?? ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b ?? ?? ?? 89 ?? ?? ?? 33 c0 8d ?? ?? ?? ab 8d ?? ?? ?? 50 68 00 90 42 00 68 ff ff 1f 00 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b ?? ?? 8b ?? ?? ?? ?? ?? 3b c3 74 ?? 48 50 ff ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 6a 02 53 53 8d ?? ?? ?? 50 ff ?? ?? 6a ff 6a ff ff d6 85 c0 7c ?? 6a 02 53 53 8d ?? ?? ?? 50 ff ?? ?? 6a fe 6a ff ff d6 85 c0 7c ?? 6a 20 53 8d ?? ?? ?? 50 68 20 90 42 00 68 9f 01 12 00 8d ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 85 c0 7c ?? 53 53 6a 08 8d ?? ?? ?? 50 8d ?? ?? ?? 50 53 53 53 ff ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ff d7 68 18 90 42 00 6a 01 ff ?? ?? ?? ?? ?? ff ?? ?? ff d7 5f 5e 5b 8b e5 5d c2 08 00}
        $hex6 = { 55 8b ec 51 68 c2 7e 42 00 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 8d ?? ?? 51 68 02 23 00 00 6a 00 50 ff ?? ?? ?? ?? ?? 85 c0 7c ?? a1 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 85 c0 75 ?? b8 53 50 43 33 68 00 00 40 00 50 ff ?? ?? ?? ?? ?? ff ?? ?? c9 c3}
        $hex7 = { 55 8b ec 83 ec 64 53 56 57 ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? ff ?? ?? ff ?? ?? e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 33 db 53 53 ff ?? ?? ?? ?? ?? 50 68 4d 10 40 00 53 53 53 53 53 6a ff ff ?? ?? ?? ?? ?? b8 00 04 00 00 e8 ?? ?? ?? ?? 8b f4 89 ?? ?? 89 ?? ?? e9 ?? ?? ?? ?? 8d ?? ?? 50 56 c7 ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 83 ?? ?? ?? 75 ?? 6a 30 53 ff ?? ?? ?? ?? ?? 3b c3 74 ?? 8b ?? ?? 8b ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? c6 ?? ?? ?? 8d ?? ?? 89 ?? ?? 89 ?? 8d ?? ?? 89 ?? ?? 89 ?? 8b ?? ?? ?? ?? ?? 89 ?? c7 ?? ?? ?? ?? ?? ?? 89 ?? ?? a3 ?? ?? ?? ?? eb ?? 33 c0 3b c3 74 ?? 8d ?? ?? e8 ?? ?? ?? ?? ff ?? ?? e9 ?? ?? ?? ?? ff ?? ?? ff ?? ?? ?? ?? ?? e9 ?? ?? ?? ?? a1 ?? ?? ?? ?? b9 38 90 42 00 eb ?? 8b ?? ?? 3b ?? ?? 74 ?? 8b ?? 3b c1 75 ?? 33 ff 3b fb 0f ?? ?? ?? ?? ?? 8b ?? ?? 48 74 ?? 48 74 ?? 48 48 74 ?? 48 74 ?? 48 74 ?? 48 74 ?? 48 75 ?? 57 8d ?? ?? e8 ?? ?? ?? ?? eb ?? 8b f8 eb ?? 8d ?? ?? 8b ?? eb ?? 8b ?? ?? 3b ?? ?? 74 ?? 8b ?? 3b c1 75 ?? 33 c0 3b c3 74 ?? 8b f0 e8 ?? ?? ?? ?? eb ?? 8d ?? ?? 50 e8 ?? ?? ?? ?? eb ?? e8 ?? ?? ?? ?? ff ?? ?? eb ?? ff ?? ?? 8b cf e8 ?? ?? ?? ?? 3b c3 74 ?? 8b f0 e8 ?? ?? ?? ?? eb ?? 57 8d ?? ?? e8 ?? ?? ?? ?? eb ?? 8d ?? ?? e8 ?? ?? ?? ?? 89 ?? ?? ff ?? ?? 8b ?? ?? 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 39 ?? ?? 74 ?? 53 56 ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8d ?? ?? 5f 5e 5b c9 c2 08 00}
		$hex8 = { 53 56 57 ff ?? ?? ?? ?? ?? 0f b7 c0 33 ff 57 6a 04 8b c8 68 04 e2 41 00 c1 e9 08 c0 e0 04 6a 1a 0a c8 6a ff 88 ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 8b d8 6a 3c 53 ff d6 59 59 85 c0 74 ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 57 e8 ?? ?? ?? ?? 68 a4 e0 41 00 ff ?? ?? ?? ?? ?? 57 ff ?? ?? ?? ?? ?? 6a 3e 53 ff d6 59 59 85 c0 74 ?? 6a 01 e8 ?? ?? ?? ?? eb ?? 8b ?? ?? ?? ?? ?? b8 00 20 00 00 66 ?? ?? ?? ?? ?? ?? 75 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 e8 03 00 00 ff ?? ?? ?? ?? ?? 57 ff ?? ?? ?? ?? ?? 8b ?? ?? ?? 2b c7 74 ?? 48 75 ?? ff ?? ?? ?? ff ?? ?? ?? ?? ?? 33 c0 40 e8 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 85 c0 74 ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 57 57 56 68 10 1c 40 00 57 57 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? eb ?? e8 ?? ?? ?? ?? 5f 5e b0 01 5b c2 0c 00}
		$hex9 = { 55 8b ec 83 e4 f8 81 ec 94 01 00 00 53 56 57 68 c0 bb 41 00 68 d4 bb 41 00 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8b d8 85 db 75 ?? 8b ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 8d ?? ?? ?? 50 6a 40 6a 07 8d ?? ?? 56 ff d7 85 c0 74 ?? b8 91 1b 40 00 2b c6 83 e8 05 89 ?? ?? 8d ?? ?? ?? 50 ff ?? ?? ?? c6 ?? ?? 6a 07 56 c6 ?? ?? ?? c6 ?? ?? ?? ff d7 8d ?? ?? ?? 50 68 02 02 00 00 ff ?? ?? ?? ?? ?? 6a 0d e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff ?? ?? ff ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 90 e0 41 00 6a 01 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? 50 6a 40 6a 02 53 ff d7 85 c0 74 ?? b8 8b ff 00 00 66 ?? ?? 8d ?? ?? ?? 50 ff ?? ?? ?? 6a 02 53 ff d7 5f 5e 33 c0 5b 8b e5 5d c2 04 00}
		$hex10 ={ 55 8b ec 83 ec 18 a0 ?? ?? ?? ?? 83 ?? ?? ?? 83 ?? ?? ?? 53 56 0f b6 c0 57 c7 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? 39 ?? ?? 73 ?? 2b ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? 2b c4 89 ?? ?? 89 ?? ?? 8b ?? ?? 8d ?? ?? 50 ff ?? ?? 53 6a 05 ff ?? ?? ?? ?? ?? 89 ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 33 c0 03 d8 6a 01 8d ?? ?? 57 68 e8 c1 41 00 ff d6 84 c0 75 ?? 6a 01 57 68 08 c2 41 00 ff d6 84 c0 75 ?? 6a 01 57 68 2c c2 41 00 ff d6 84 c0 75 ?? 6a 01 57 68 4c c2 41 00 ff d6 84 c0 75 ?? 6a 01 57 68 6c c2 41 00 ff d6 84 c0 75 ?? 6a 01 57 68 8c c2 41 00 ff d6 84 c0 74 ?? 8d ?? ?? ?? ?? ?? 50 68 00 e0 41 00 6a 01 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 85 c0 7c ?? 6a 00 ff ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ff ?? ?? ?? ?? ?? 8b ?? 85 c0 0f ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? 8d ?? ?? 5f 5e 5b c9 c3}
		$hex11 ={ 55 8b ec 81 ec ac 00 00 00 53 56 57 6a 20 6a 07 8d ?? ?? 50 68 6c e0 41 00 68 89 00 12 00 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 8b d8 85 db 0f ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 6a 05 6a 10 8d ?? ?? 50 8d ?? ?? 50 ff ?? ?? ff d6 8b d8 bf 05 00 00 80 3b df 74 ?? 85 db 75 ?? 8b ?? ?? b8 80 00 04 00 23 c8 3b c8 75 ?? 6a 01 6a 18 8d ?? ?? 50 8d ?? ?? 50 ff ?? ?? ff d6 3b c7 74 ?? 85 c0 75 ?? 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 6a 08 8d ?? ?? 50 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 6a 10 8d ?? ?? 50 68 14 e2 41 00 e8 ?? ?? ?? ?? 83 c4 0c 33 db eb ?? bb bb 00 00 c0 ff ?? ?? ff ?? ?? ?? ?? ?? 85 db 7d ?? 81 cb 00 00 01 00 5f 5e 8b c3 5b c9 c3}
	condition:
		(5 of them) or (any of ($hex*)) or (any of ($s*))
}

rule TrojanSirefefZerroAccessANModule
{
	meta:
		Description  = "Trojan.Sirefef.sm"
		ThreatLevel  = "5"

	strings:
		$ = "%s\\%s\\%08x.@" ascii wide
		$ = "%s\\%s\\%s" ascii wide
		$ = "InstallFlashPlayer.exe" ascii wide
		$ = "get/flashplayer/update/current/install/install_all_win_%s_sgn.z" ascii wide
		$ = "download/C/C/0/CC0BD555-33DD-411E-936B-73AC6F95AE11/IE8-WindowsXP-x86-ENU.exe" ascii wide
		$ = "\\??\\%08x" ascii wide
		$ = "80000032.32" ascii wide
		$ = "\\GLOBAL??\\{D1C8BD9B-9DF7-4fb6-A1C3-D96202C79FC0}" ascii wide
		$ = "http://%.*s/_ylt=3648C868A1DB;" ascii wide

		
		$hex0 = { 56 8b ?? ?? ?? 33 c0 8d ?? ?? 87 ?? 85 c0 74 ?? 6a 00 50 6a 00 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 8d ?? ?? 83 c8 ff f0 ?? ?? ?? 75 ?? 85 f6 74 ?? 8b ?? 8b ?? 6a 01 8b ce ff d0 83 c8 ff 8d ?? ?? 87 ?? 83 f8 ff 74 ?? 50 ff ?? ?? ?? ?? ?? 8b ?? 8b ?? ?? 8b ce ff d0 8d ?? ?? 83 ca ff f0 ?? ?? ?? 75 ?? 85 f6 74 ?? 8b ?? 8b ?? 6a 01 8b ce ff d2 5e c2 08 00}
		$hex1 = { 57 8b ?? ?? ?? ?? ?? 68 30 75 00 00 ff d7 a1 ?? ?? ?? ?? 85 c0 74 ?? 56 eb ?? 8d 9b 00 00 00 00 68 30 75 00 00 8b f0 ff d7 a1 ?? ?? ?? ?? 3b f0 75 ?? 5e 6a 00 ff ?? ?? ?? ?? ??}
		$hex2 = { 83 ec 5c 56 8d ?? ?? ?? 50 68 ff 01 0f 00 83 ce ff 56 ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b ?? ?? ?? 57 8d ?? ?? ?? 51 6a 01 6a 00 68 90 61 01 10 68 ff 01 0f 00 52 ff ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 85 c0 78 ?? 8b ?? ?? ?? 6a 04 8d ?? ?? ?? 50 6a 0c 51 ff ?? ?? ?? ?? ?? 6a 40 8d ?? ?? ?? 6a 00 52 c7 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? ?? 83 c4 0c 8d ?? ?? ?? 50 8b ?? ?? ?? 8d ?? ?? ?? 51 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 52 6a 00 50 c7 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 85 c0 74 ?? 8b ?? ?? ?? 51 ff d7 8b ?? ?? ?? 8b ?? ?? ?? 52 ff d7 8b ?? ?? ?? 50 ff d7 5f 8b c6 5e 83 c4 5c c2 08 00}
		$hex3 = { 56 8b f2 e8 ?? ?? ?? ?? 85 c0 74 ?? 83 ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 75 ?? e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 20 8b 00 10 6a 00 6a 00 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? b8 01 00 00 00 5e c3 33 c0 5e c3}
		$hex4 = { 53 8b d9 8b ca e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 56 68 20 ca 01 10 ff ?? ?? ?? ?? ?? 8b f0 ff ?? ?? ?? ?? ?? ba f8 34 01 10 8b ce 57 8b ff 66 ?? ?? 66 ?? ?? 75 ?? 66 85 ff 74 ?? 66 ?? ?? ?? 66 ?? ?? ?? 75 ?? 83 c1 04 83 c2 04 66 85 ff 75 ?? 33 c9 eb ?? 1b c9 83 d9 ff 85 c9 75 ?? 68 10 35 01 10 50 ff ?? ?? ?? ?? ?? 83 c4 08 85 c0 74 ?? 68 30 be 00 10 c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 6a 00 6a 00 68 b0 04 00 00 68 a0 89 00 10 6a 00 6a 00 ff d6 8b ?? ?? ?? ?? ?? 50 ff d7 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 20 83 00 10 6a 00 6a 00 ff d6 50 ff d7 5f 5e b8 01 00 00 00 5b c3 e8 ?? ?? ?? ?? 85 c0 74 ?? 68 30 be 00 10 c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 80 bd 00 10 6a 00 6a 00 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 5f 5e b8 01 00 00 00 5b c3 5f 5e 33 c0 5b c3 83 ?? ?? ?? ?? ?? ?? 74 ?? 8b c3 e8 ?? ?? ?? ?? b8 01 00 00 00 5b c3 33 c0 5b c3}


	condition:
		(5 of them) or (any of ($hex*))
}

rule TrojanSirefefZerroAccessPlayloadModule
{
	meta:
		Description  = "Trojan.Sirefef.sm"
		ThreatLevel  = "5"

	strings:
		$ = "U\\80000032.@" ascii wide
		$ = "\\\\.\\globalroot\\systemroot\\system32\\mswsock.dll" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.AcceptEx" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.GetAcceptExSockaddrs" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.NSPStartup" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.TransmitFile" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.getnetbyname" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.inet_network" ascii wide
		$ = "%sU\\%08x.@" ascii wide
		$ = "\\??\\%s@" ascii wide
		$ = "\\??\\%sU" ascii wide
		$ = "\\registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters" ascii wide
		$ = "\\KnownDlls\\mswsock.dll" ascii wide
		$ = "\\systemroot\\assembly" ascii wide
		$ = "GAC_MSIL" ascii wide
		$ = "GAC" ascii wide
		$ = "????????.@" ascii wide
		$ = "%08x.@" ascii wide
		$ = "%08x.$" ascii wide
		$ = "%08x.~" ascii wide
		
		$ = "\\systemroot\\assembly\\GAC\\Desktop.ini" ascii wide

	condition:
		(5 of them)
}

rule TrojanSirefefZerroAccessPluginModule
{
	meta:
		Description  = "Trojan.Sirefef.sm"
		ThreatLevel  = "5"

	strings:
		$hex0 = { 55 8b ec 81 ec 94 01 00 00 56 68 30 40 00 10 68 00 00 10 00 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 8b f0 81 fe 00 00 00 40 75 ?? ff ?? ?? ff ?? ?? ?? ?? ?? 85 f6 8b ?? ?? ?? ?? ?? 7c ?? 8d ?? ?? ?? ?? ?? 50 68 02 02 00 00 ff ?? ?? ?? ?? ?? 85 c0 75 ?? e8 ?? ?? ?? ?? 6a 20 68 60 ea 00 00 b9 80 40 00 10 e8 ?? ?? ?? ?? 69 c0 e8 03 00 00 50 6a 00 68 b7 15 00 10 6a 00 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 85 c0 74 ?? ff ?? ?? ff ?? ?? ?? ?? ?? 6a ff ff ?? ?? 6a 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ff d6 a1 ?? ?? ?? ?? 85 c0 74 ?? b9 fb 15 00 10 ff ?? ?? e8 ?? ?? ?? ?? 68 28 40 00 10 6a 01 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff d6}
		$hex1 = { 81 ?? ?? ?? ?? ?? 56 57 8b f9 75 ?? b9 fb 15 00 10 89 ?? ?? ?? ?? ?? ff ?? ?? 8b ?? ?? ?? ?? ?? 68 08 32 00 10 57 ff d6 59 59 50 b9 80 40 00 10 e8 ?? ?? ?? ?? 68 f0 31 00 10 57 ff d6 59 59 33 c9 8b d0 41 e8 ?? ?? ?? ?? 33 c0 50 50 50 68 85 16 00 10 50 50 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 5f 40 5e c3}
		$hex2 = { 55 8b ec 81 ec 90 00 00 00 53 56 57 6a 40 5e 8b d9 6a 04 8b c6 66 ?? ?? ?? 58 33 ff 57 66 ?? ?? ?? 57 8d ?? ?? 50 ff ?? ?? c7 ?? ?? ?? ?? ?? ?? c6 ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? c6 ?? ?? ?? ff ?? ?? ?? ?? ?? 84 c0 0f ?? ?? ?? ?? ?? 6a 20 8d ?? ?? 6a 07 89 ?? ?? 8d ?? ?? 50 8d ?? ?? 50 89 ?? ?? 68 98 00 10 00 8d ?? ?? 56 c7 ?? ?? ?? ?? ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? ff ?? ?? ?? ?? ?? 85 c0 7c ?? 57 57 6a 18 68 0c 40 00 10 57 6a 60 8d ?? ?? ?? ?? ?? 50 8d ?? ?? 50 ff ?? e8 ?? ?? ?? ?? 85 c0 7c ?? 8d ?? ?? ?? ?? ?? 33 c9 03 c1 80 ?? ?? ?? 75 ?? 8b ?? ?? 81 f9 30 30 31 00 74 ?? 81 f9 30 30 32 00 75 ?? 66 ?? ?? ?? ?? 75 ?? 8b ?? ?? 89 ?? ?? eb ?? 66 ?? ?? ?? ?? 75 ?? 6a 10 8d ?? ?? 8d ?? ?? 59 f3 ?? 33 ff 8b ?? 3b cf 75 ?? 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 66 ?? ?? ?? 75 ?? e8 ?? ?? ?? ?? 33 d2 b9 80 51 01 00 f7 f1 6a 4c 53 66 ?? ?? ?? 8d ?? ?? 50 ff ?? ?? e8 ?? ?? ?? ?? 39 ?? ?? 75 ?? c7 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 57 8b cb 89 ?? ?? e8 ?? ?? ?? ?? 5f 5e 5b c9 c2 04 00}
		
		$hex3 = { 55 8b ec 83 ec 74 53 56 57 be 30 00 fe 7f 56 ff ?? ?? ?? ?? ?? 59 8d ?? ?? ?? e8 ?? ?? ?? ?? 89 ?? ?? 68 94 60 00 10 56 ff ?? ?? ff ?? ?? ?? ?? ?? 59 59 50 ff ?? ?? ?? ?? ?? 59 59 33 db 53 53 ff ?? ?? ?? ?? ?? 8b f0 3b f3 0f ?? ?? ?? ?? ?? 6a 70 8d ?? ?? 53 50 e8 ?? ?? ?? ?? 83 c4 0c 6a 70 8d ?? ?? 50 33 ff 6a 09 47 56 c7 ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 85 c0 74 ?? ff ?? ?? ?? ?? ?? 85 c0 74 ?? 9c 81 ?? ?? ?? ?? ?? ?? 9d 90 68 08 70 00 10 57 8b ?? ?? ?? ?? ?? ff d7 85 c0 75 ?? 38 ?? ?? ?? ?? ?? 75 ?? ff ?? ?? ff ?? ?? 56 e8 ?? ?? ?? ?? 38 ?? ?? ?? ?? ?? 75 ?? 68 00 70 00 10 6a 01 ff d7 85 c0 74 ?? 56 ff ?? ?? ?? ?? ?? 33 c0 8d ?? ?? 5f 5e 5b c9 c2 04 00}
		$hex4 = { 55 8b ec 51 53 56 57 68 24 70 00 10 68 00 00 10 00 8d ?? ?? 50 ff ?? ?? ?? ?? ?? 8b f8 81 ff 00 00 00 40 75 ?? ff ?? ?? ff ?? ?? ?? ?? ?? 33 f6 3b fe 7c ?? 56 56 ff ?? ?? 68 88 13 00 10 56 56 ff ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 8b f8 3b fe 74 ?? ff ?? ?? ff ?? ?? ?? ?? ?? 57 c6 ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 56 56 57 ff ?? ?? ?? ?? ?? 57 ff d3 ff ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ff d3 ff ?? ?? ff ?? ?? ?? ?? ??}
		$hex5 = { 53 56 57 8b d9 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 9c 81 ?? ?? ?? ?? ?? ?? 9d 90 53 ff ?? ?? ?? ?? ?? 59 6a 02 5a 8d ?? ?? ?? 33 c9 f7 e2 0f 90 c1 33 ff f7 d9 0b c1 50 57 ff ?? ?? ?? ?? ?? 8b f0 3b f7 74 ?? 53 68 50 61 00 10 56 ff ?? ?? ?? ?? ?? 83 c4 0c 57 57 56 68 77 14 00 10 57 57 ff ?? ?? ?? ?? ?? 3b c7 74 ?? 50 ff ?? ?? ?? ?? ?? 33 c0 40 eb ?? 56 ff ?? ?? ?? ?? ?? 33 c0 5f 5e 5b c3}

	condition:
		any of ($hex*)
}

rule TrojanSirefefZerroAccessPluginModuleZooCliccer
{
	meta:
		Description  = "Trojan.ZooClicker.sm"
		ThreatLevel  = "5"

	strings:
		$ = "%s\\00000001.@" ascii wide                                                                                                                                                                                                                                                                                                                                                                   
		$ = "z00clicker3"  ascii wide  
		$ = "z00clicker"  ascii wide

	condition:
		any of them
}

rule TrojanSirefefZerroAccess2016
{
	meta:
		Description  = "Trojan.Sirefef.E.sm"
		ThreatLevel  = "5"

	strings:

		$ = "GoogleUpdate.exe" ascii wide
		$ = "%08x.@" ascii wide
		$ = "%08x.$" ascii wide
		$ = "%08x.~" ascii wide

		$s1 = "\\Google\\Desktop\\Install\\{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\\#." ascii wide
		$s2 = "\\BaseNamedObjects\\Restricted\\{12E9D947-EDF5-4191-AADB-F51815F004D8}" ascii wide
		$s3 = "\\BaseNamedObjects\\Restricted\\{889E2280-F15E-4330-A3F4-D4EEF899AAF6}" ascii wide
		$s4 = "\\BaseNamedObjects\\Restricted\\{1FD06E7A-B215-4ae2-B209-AC869A3DF0B7}" ascii wide
		$s5 = "\\BaseNamedObjects\\Restricted\\{A3D35150-6823-4462-8C6E-7417FF841D7A}" ascii wide
		$s6 = "80000000.@" ascii wide
		$s7 = "=cccctp=ddddt:=rrrrt<=sssst" ascii wide
		$s8 = "=ccccta=ddddt+=rrrrt-=sssst" ascii wide

	condition:
		(3 of them) or (any of ($s*))
}rule TrojanUpatreSample
{
    meta:
        Description = "Trojan.Upatre.vb"
        ThreatLevel = "5"

    strings:
        $hex_string = { 52 ba 6c 6c 00 00 52 ba 73 66 2e 64 52 ba 32 5c 71 61 52 ba 74 65 6d 33 52 ba 5c 73 79 73 52}

    condition:
        $hex_string
}rule TrojanVirtoolObfuscator
{
		meta:
			Description = "Trojan.Obfuscator.rc"
			ThreatLevel = "5"
			
		strings:
			$ = "1346243623461" ascii wide
			$ = "3nterface" ascii wide
		condition:
			all of them
}rule TrojanPSWTepferSample
{
	meta:
		Description  = "Trojan.Tepfer.sm"
		ThreatLevel  = "5"

	strings:
		$ = "Software\\BPFTP"                                    ascii wide
		$ = "\\BulletProof Software\\BulletProof FTP Client"     ascii wide
		$ = "Software\\BPFTP\\Bullet Proof FTP"                  ascii wide
		$ = "Software\\NCH Software\\ClassicFTP\\FTPAccounts"    ascii wide
		$ = "\\GlobalSCAPE\\CuteFTP"                             ascii wide
		$ = "\\GlobalSCAPE\\CuteFTP Pro"                         ascii wide
		$ = "\\GlobalSCAPE\\CuteFTP Lite"                        ascii wide
		$ = "\\CuteFTP"                                          ascii wide
		$ = "\\GPSoftware\\Directory Opus\\ConfigFiles\\ftp.oxc" ascii wide
		$ = "SOFTWARE\\Far\\Plugins\\FTP\\Hosts"                 ascii wide
		$ = "SOFTWARE\\Far2\\Plugins\\FTP\\Hosts"                ascii wide
		$ = "Software\\Far\\Plugins\\FTP\\Hosts"                 ascii wide
		$ = "Software\\Far2\\Plugins\\FTP\\Hosts"                ascii wide
		$ = "Software\\Far\\SavedDialogHistory\\FTPHost"         ascii wide
		$ = "Software\\Far2\\SavedDialogHistory\\FTPHost"        ascii wide
		$ = "Software\\Ghisler\\Windows Commander"				 ascii wide
		$ = "Software\\Ghisler\\Total Commander"				 ascii wide
		$ = "Software\\Sota\\FFFTP"                              ascii wide
		$ = "Software\\FileZilla"                                ascii wide
		$ = "FileZilla3"                                         ascii wide
		$ = "FlashFXP"                                           ascii wide
		$ = "FTP Commander Pro"                                  ascii wide
		$ = "FTP Navigator"                                      ascii wide
		$ = "FTP Commander"                                      ascii wide
		$ = "FTP Commander Deluxe"                               ascii wide
		$ = "Software\\FTP Explorer\\Profiles"                   ascii wide
		$ = "\\FTP Explorer\\profiles.xml"                       ascii wide
		$ = "Windows/Total Commander"                            ascii wide
		$ = "FTP Commander"                                      ascii wide
		$ = "BulletProof FTP Client"                             ascii wide
		$ = "TurboFTP"                                           ascii wide
		$ = "SoftX FTP Client"                                   ascii wide
		$ = "LeapFTP"                                            ascii wide
		$ = "WinSCP"                                             ascii wide
		$ = "32bit FTP"                                          ascii wide
		$ = "FTP Control"                                        ascii wide
		$ = "SecureFX"                                           ascii wide
		$ = "BitKinex"                                           ascii wide
		$ = "CuteFTP"                                            ascii wide
		$ = "WS_FTP"                                             ascii wide
		$ = "FFFTP"                                              ascii wide
		$ = "Core FTP"                                           ascii wide
		$ = "WebDrive"                                           ascii wide
		$ = "Classic FTP"                                        ascii wide
		$ = "Fling"                                              ascii wide
		$ = "NetDrive"                                           ascii wide
		$ = "FileZilla"                                          ascii wide
		$ = "FTP Explorer"                                       ascii wide
		$ = "SmartFTP"                                           ascii wide
		$ = "FTPRush"                                            ascii wide
		$ = "UltraFXP"                                           ascii wide
		$ = "Frigate3 FTP"                                       ascii wide
		$ = "BlazeFtp"				ascii wide
		$ = "Software\\LeechFTP"	ascii wide
		$ = "SiteInfo.QFP"			ascii wide
		$ = "WinFTP"				ascii wide
		$ = "FreshFTP"				ascii wide
		$ = "BlazeFtp"				ascii wide
	condition:
		9 of them
}rule TrojanZeusZbotSampleA
{
	meta:
		Description  = "Trojan.ZBot.sm"
		ThreatLevel  = "5"

	strings:
		$ = "-m" ascii wide
		$ = "-m%p" ascii wide
		$ = ":d\\r\\ndel" ascii wide
		$ = "@echo off\\r\\n%s\\r\\ndel /F" ascii wide
		$hex0 = { 83 EC 0C 53 55 33 DB 56 8B C2 33 ED 57 89 44 24 18 89 4C 24 10 39 5C 24 20 0F 8E ?? ?? ?? ?? 8B 04 A8 83 3C C5 }
		$hex1 = { E8 ?? ?? ?? ?? 83 C4 04 C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 15 ?? ?? ?? ?? 0F 83 ?? ?? ?? ?? C7 45 F4 ?? ?? ?? ?? C7 45 F4 ?? ?? ?? ?? C7 45 F4 ?? ?? ?? ?? C7 45 F4 ?? ?? ?? ?? C7 45 F4 ?? ?? ?? ?? C7 45 F4 ?? ?? ?? ?? C7 45 F4 ?? ?? ?? ?? C7 45 F4 ?? ?? ?? ?? C7 45 F4 ?? ?? ?? ?? 8B 45 08 83 C0 08 A3 ?? ?? ?? ?? 8B 4D FC 51 8B 15 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? }
        $hex2 = { 6A 02 6A 00 FF 15 ?? ?? ?? ?? 8B F0 85 F6 74 08 56 E8 ?? ?? ?? ?? EB 02 8A C3 84 C0 74 28 F6 44 24 36 08 75 0A E8 ?? ?? ?? ?? 83 4C 24 36 08 F6 44 24 36 40 75 0A E8 ?? ?? ?? ?? 83 4C 24 36 40 56 E8 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 8A C3 EB 02 32 C0 5E 5B 8B E5 5D C3 }
        $hex3 = { 55 8b ec 81 ec 70 03 00 00 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 50 68 28 59 40 00 8d ?? ?? ?? ?? ?? 68 6c 02 00 00 50 e8 ?? ?? ?? ?? 83 c4 14 85 c0 7e ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 84 c0 74 ?? b0 01 eb ?? 32 c0 c9 c2 04 00}
        $hex4 = { 55 8b ec 83 e4 f8 81 ec 4c 02 00 00 53 8b ?? ?? ?? ?? ?? 56 57 33 ff c6 ?? ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 57 6a 02 e8 ?? ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 83 f8 ff 0f ?? ?? ?? ?? ?? 8d ?? ?? ?? 50 ff ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b ?? ?? ?? 3b cf 0f ?? ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? 33 c0 39 ?? ?? ?? 76 ?? 8b ?? ?? ?? 39 ?? ?? 0f ?? ?? ?? ?? ?? 40 3b ?? ?? ?? 72 ?? 51 e8 ?? ?? ?? ?? 89 ?? ?? ?? 3b c7 0f ?? ?? ?? ?? ?? ff ?? ?? ?? 57 68 00 04 00 00 ff ?? ?? ?? ?? ?? 8b f0 3b f7 0f ?? ?? ?? ?? ?? 8d ?? ?? ?? 50 56 e8 ?? ?? ?? ?? 56 8b f8 ff d3 85 ff 74 ?? 8b ?? ?? ?? 3b ?? ?? ?? ?? ?? 75 ?? ff ?? ff ?? ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 75 ?? 8b ?? 50 a1 ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 8b ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 50 8d ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 ?? 8b ?? ?? ?? 8b ?? ?? ?? 8b ?? ?? ?? ff ?? ?? ?? ff ?? ?? ?? ff ?? ?? ?? 89 ?? ?? ff ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 ?? c6 ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 33 ff ff ?? ?? ?? ff d3 8d ?? ?? ?? 50 ff ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? ff ?? ?? ?? ff d3 39 ?? ?? ?? 0f ?? ?? ?? ?? ?? ff ?? ?? ?? e8 ?? ?? ?? ?? 8a ?? ?? ?? 5f 5e 5b 8b e5 5d c3}


	condition:
		(3 of them) or (any of ($hex*))
}
rule TrojanSpyWin32UrsnifASample
{
	meta:
		Description  = "Trojan.Ursnif.sm"
		ThreatLevel  = "5"

	strings:
		$ = "CreateProcessNotify" ascii wide
		$ = "rundll32" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls" ascii wide
		$ = "iexplore.exe" ascii wide
		$ = "firefox.exe" ascii wide
		$ = "Software\\AppDataLow\\Software\\Microsoft\\Internet Explorer\\Security\\AntiPhishing" ascii wide
		$ = "/UPD" ascii wide
		$ = "/sd %lu" ascii wide
		$ = "%lu.bat" ascii wide
		$ = "attrib -r -s -h %%1" ascii wide
		$ = "S:(ML;;NW;;;LW)" ascii wide
		$ = "D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GA;;;AU)(A;OICI;GA;;;BA)" ascii wide
		$ = "%lu.exe" ascii wide                                                                                                                                                         
		$ = "mashevserv.com" ascii wide                                                                       
		$ = "ericpotic.com" ascii wide                                                                                                                                                                                                                             
		$ = "version=%u&user=%x%x%x%x&server=%u&id=%u&crc=%x&aid=%u" ascii wide                                                                                                       
		$ = "CHROME.DLL" ascii wide                                                                                                                                                                                                                                   
		$ = "chrome.exe" ascii wide                                                                            
		$ = "opera.exe"  ascii wide                                                                            
		$ = "safari.exe" ascii wide                                                                            
		$ = "explorer.exe" ascii wide

	condition:
		6 of them
}rule ChirBSample
{
    meta:
        Description = "Virus.Chir.B.vb"
        ThreatLevel = "5"

    strings:
        $ = "runouce.exe" ascii wide
        $ = "imissyou@btamail.net.cn" ascii wide
        $ = "ChineseHacker-2" ascii wide

    condition:
        all of them
}rule FileVirusWin32MaganASample
{
	meta:
		Description  = "Virus.Madang.sm"
		ThreatLevel  = "5"

	strings:
		$hex_string = { 60 78 ?? 79 ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? ?? e8 ?? ?? ?? ?? 61 78 ?? 79 ?? ?? 68 ?? ?? ?? ?? C3 }

	condition:
		any of them
}rule WormWin32CridexSamlpeE
{
	meta:
		Description  = "Worm.Cridex.sm"
		ThreatLevel  = "5"

	strings:
		$ = "Software\\Microsoft\\Windows NT\\C%08X" ascii wide   
		$ = "<server><![CDATA[%%u.%%u.%%u.%%u:%%u]]>" ascii wide
		$ = "KB%08d.exe" ascii wide
		$ = "Local\\XME%08X" ascii wide
		$ = "Local\\XMM%08X" ascii wide
		$ = "Local\\XMI%08X" ascii wide
		$ = "Local\\XMS%08X" ascii wide                                                                                                     
		$ = "Local\\XMF%08X" ascii wide                                                                                                                                                                                                              
		$ = "Local\\XMR%08X" ascii wide                                                                                                                                                                                                        
		$ = "Local\\XMQ%08X" ascii wide                                                                                                     
		$ = "Local\\XMB%08X" ascii wide 
	condition:
		2 of them
}rule WormWin32DorkbotSamlpeA
{
 meta:
  Description  = "Worm.Dorkbot.sm"
  ThreatLevel  = "5"

 strings:
	$ = "from removing our bot file!" ascii wide
	$ = "from moving our bot file" ascii wide
	$ = "Message hijacked!" ascii wide
	$ = "popgrab" ascii wide
	$ = "ftpgrab" ascii wide
	$ = "s.Blocked possible browser exploit pack call on URL" ascii wide
	$ = "webroot." ascii wide
	$ = "fortinet." ascii wide
	$ = "virusbuster.nprotect." ascii wide
	$ = "gdatasoftware." ascii wide
	$ = "virus." ascii wide
	$ = "precisesecurity." ascii wide
	$ = "lavasoft." ascii wide
	$ = "heck.tc" ascii wide
	$ = "emsisoft." ascii wide
	$ = "onlinemalwarescanner." ascii wide
	$ = "onecare.live." ascii wide
	$ = "f-secure." ascii wide
	$ = "bullguard." ascii wide
	$ = "clamav." ascii wide
	$ = "pandasecurity." ascii wide
	$ = "sophos." ascii wide
	$ = "malwarebytes." ascii wide
	$ = "sunbeltsoftware." ascii wide
	$ = "norton." ascii wide
	$ = "norman." ascii wide
	$ = "mcafee." ascii wide
	$ = "symantec" ascii wide
	$ = "comodo." ascii wide
	$ = "avast." ascii wide
	$ = "avira." ascii wide
	$ = "avg." ascii wide
	$ = "bitdefender." ascii wide
	$ = "eset." ascii wide
	$ = "kaspersky." ascii wide
	$ = "trendmicro." ascii wide
	$ = "iseclab." ascii wide
	$ = "virscan." ascii wide
	$ = "garyshood." ascii wide
	$ = "viruschief." ascii wide
	$ = "jotti." ascii wide
	$ = "threatexpert." ascii wide
	$ = "novirusthanks." ascii wide
	$ = "virustotal." ascii wide
	$ = "you stupid cracker" ascii wide
	$ = "ngrBot Error" ascii wide
	$ = "Slowloris]: Finished flood on" ascii wide
	$ = "UDP]: Finished flood on" ascii wide
	$ = "SYN]: Finished flood on" ascii wide
	$ = "USB]: Infected %s" ascii wide
	$ = "MSN]: Updated MSN spread message to" ascii wide
	$ = "MSN]: Updated MSN spread interval to" ascii wide
	$ = "HTTP]: Updated HTTP spread message to" ascii wide
	$ = "HTTP]: Injected value is now %s." ascii wide
	$ = "HTTP]: Updated HTTP spread interval to" ascii wide
	$ = "Visit]: Visited" ascii wide
	$ = "DNS]: Blocked" ascii wide
	$ = "RSOCK4]: Started rsock4" ascii wide
	$ = "Visit]: Error visitng" ascii wide
	$ = "FTP Login]: %s" ascii wide
	$ = "POP3 Login]: %s" ascii wide
	$ = "FTP Infect]: %s was iframed" ascii wide
	$ = "HTTP Login]: %s" ascii wide
	$ = "HTTP Traffic]: %s" ascii wide
	$ = "Ruskill]: Detected File:" ascii wide
	$ = "Ruskill]: Detected DNS:" ascii wide
	$ = "Ruskill]: Detected Reg:" ascii wide
	$ = "PDef+]: %s" ascii wide
	$ = "DNS]: Blocked DNS" ascii wide
	$ = "MSN]: %s" ascii wide
	$ = "HTTP]: %s" ascii wide
 condition:
  8 of them
}

rule WormWin32DorkbotSamlpeB
{
 	meta:
 		Description  = "Worm.Dorkbot.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = "http://ht.ly/jZH8A?yd=" ascii wide
		$ = "DecriptedFiles" ascii wide
		$ = "Infected Drive: %s" ascii wide
		$a = "snkb00pt" ascii wide

 	condition:
 		(3 of them) or $a
}rule WormWin32PhorpiexSampleM
{
	meta:
		Description  = "Worm.Phorpiex.sm"
		ThreatLevel  = "5"

	strings:
		$ = "paltalk.exe" ascii wide
		$ = "Xfire.exe" ascii wide
		$ = "googletalk.exe" ascii wide
		$ = "Skype.exe" ascii wide
		$ = "http://goo.gl" ascii wide
		
		$ = "qemu" ascii wide
		$ = "virtual" ascii wide
		$ = "vmware" ascii wide
		$ = "%s\\winsvcon.txt" ascii wide
		$ = "%s\\rmrf%i%i%i%i.bat" ascii wide
		$ = "%s%s.txt" ascii wide
		$ = "%s%s.zip" ascii wide
		$ = "IMG%s-JPG.scr" ascii wide
		$ = "Microsoft Windows Manager" ascii wide
		$ = "winbtc.exe" ascii wide
		$ = "winmgr.exe" ascii wide
		$ = "winraz.exe" ascii wide
		$ = "winsam.exe" ascii wide
		$ = "winsvc.exe" ascii wide
		$ = "winsvn.exe" ascii wide
		$ = ".exe" ascii wide
		$ = ".bat" ascii wide
		$ = ".vbs" ascii wide
		$ = ".pif" ascii wide
		$ = ".cmd" ascii wide
		$ = "%s\\autorun.inf" ascii wide
		
		$ = "ti piace la foto?" ascii wide
		$ = "hai visto questa foto?" ascii wide
		$ = "la foto e grandiosa!" ascii wide
		$ = "ti ricordi la Foto?" ascii wide
		$ = "conosci la persona in questa foto?" ascii wide
		$ = "chi e in questa foto?" ascii wide
		$ = "nu imi mai voi face niciodat poze!! toate ies urate ca asta." ascii wide
		$ = "spune-mi ce crezi despre poza asta." ascii wide
		$ = "asta e ce-a mai funny poza! tu ce zici?" ascii wide
		$ = "zimi ce crezi despre poza asta?" ascii wide
		$ = "pogled na ovu sliku" ascii wide
		$ = "bu resmi bakmak" ascii wide
		$ = "pozri sa na tento obr" ascii wide
		$ = "pogled na to sliko" ascii wide
		$ = "vaata seda pilti" ascii wide
		$ = "spojrzec na to zdjecie" ascii wide
		$ = "Ieskatieties " ascii wide
		$ = "kyk na hierdie foto" ascii wide
		$ = "tell me what you think of this picture i edited" ascii wide
		$ = "this is the funniest photo ever!" ascii wide
		$ = "tell me what you think of this photo" ascii wide
		$ = "i don't think i will ever sleep again after seeing this photo" ascii wide
		$ = "i cant believe i still have this picture" ascii wide
		$ = "should i make this my default picture?" ascii wide
		$ = "ken je dat foto nog?" ascii wide
		$ = "kijk wat voor een foto ik heb gevonden" ascii wide
		$ = "ik hoop dat jij het net bent op dit foto" ascii wide
		$ = "ben jij dat op dit foto?" ascii wide
		$ = "dit foto zal je echt eens bekijken!" ascii wide
		$ = "ken je dit foto al?" ascii wide
		$ = "olhar para esta foto" ascii wide
		$ = "devrais-je mettre cette photo de profile?" ascii wide
		$ = "c'est la photo la plus marrante!" ascii wide
		$ = "dis moi ce que tu pense de cette photo de moi?" ascii wide
		$ = "mes parents vont me tu" ascii wide
		$ = "creo que no voy a poder dormir m" ascii wide
		$ = "esta foto es gracios" ascii wide
		$ = "mis padres me van a matar si ven esta foto mia, que decis?" ascii wide
		$ = "mira como saliste en esta foto jajaja" ascii wide
		$ = "wie findest du das foto?" ascii wide
		$ = "hab ich dir das foto schon gezeigt?" ascii wide
		$ = "schau mal welches foto ich gefunden hab" ascii wide
		$ = "bist du das auf dem foto?" ascii wide
		$ = "kennst du das foto schon?" ascii wide
		$ = "I cant believe I still have this picture" ascii wide 
		$ = "I love your picture!" ascii wide 
		$ = "Is this you??" ascii wide 
		$ = "Picture of you???" ascii wide 
		$ = "Should I upload this picture on facebook?" ascii wide
		$ = "Someone showed me your picture" ascii wide 
		$ = "Someone told me it's your picture" ascii wide 
		$ = "Take a look at my new picture please" ascii wide 
		$ = "Tell me what you think of this picture" ascii wide 
		$ = "This is the funniest picture ever!" ascii wide 
		$ = "What do you think of my new hair" ascii wide 
		$ = "What you think of my new hair color?" ascii wide 
		$ = "What you think of this picture?" ascii wide 
		$ = "You look so beautiful on this picture" ascii wide 
		$ = "You should take a look at this picture" ascii wide 
		$ = "Your photo isn't really that great" ascii wide

	condition:
		5 of them
}rule WormWin32SillyP2PSampleH
{
	meta:
		Description  = "Worm.Silly.sm"
		ThreatLevel  = "5"

	strings:
		$ = "95BC789A" ascii wide
		$ = "svchosts.exe" ascii wide
		$ = "Failed to start dl thread." ascii wide
		$ = "wo8T#$>X&D" ascii wide

		$hex0 = { 55 8b ec 81 ec 8c 06 00 00 56 57 83 ?? ?? ?? ?? ?? ?? 8b ?? ?? b9 a5 00 00 00 8d ?? ?? ?? ?? ?? f3 ?? 68 04 01 00 00 8d ?? ?? ?? ?? ?? 50 68 68 42 40 00 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 6a 00 68 60 42 40 00 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 68 58 42 40 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 83 ?? ?? ?? ?? ?? ?? 74 ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? eb ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 68 38 42 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 14 8d ?? ?? ?? ?? ?? 50 8d ?? ?? ?? ?? ?? 50 6a 06 ff ?? ?? e8 ?? ?? ?? ?? 83 c4 10 68 00 02 00 00 6a 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 74 ?? 83 ?? ?? ?? ?? ?? ?? 74 ?? 83 ?? ?? ?? ?? ?? ?? 74 ?? eb ?? 68 64 41 40 00 68 28 42 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 eb ?? 8d ?? ?? ?? ?? ?? 50 68 0c 42 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 eb ?? 68 f0 41 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c eb ?? 68 c4 41 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 8d ?? ?? ?? ?? ?? 50 8d ?? ?? ?? ?? ?? 50 6a 06 ff ?? ?? e8 ?? ?? ?? ?? 83 c4 10 68 00 02 00 00 6a 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 83 ?? ?? ?? ?? ?? ?? 75 ?? ff ?? ?? ?? ?? ?? 6a 00 ff ?? ?? ?? ?? ?? ff ?? ?? e8 ?? ?? ?? ?? 59 6a 00 ff ?? ?? ?? ?? ??}
		$hex1 = { 55 8b ec 81 ec 14 03 00 00 57 80 ?? ?? ?? ?? ?? ?? 6a 40 59 33 c0 8d ?? ?? ?? ?? ?? f3 ?? 66 ?? aa 80 ?? ?? ?? ?? ?? ?? 6a 40 59 33 c0 8d ?? ?? ?? ?? ?? f3 ?? 66 ?? aa 6a 03 8d ?? ?? ?? ?? ?? 50 6a 00 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 80 ?? ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 83 f8 02 75 ?? 6a 05 6a 00 8d ?? ?? ?? ?? ?? 50 68 48 41 40 00 68 40 41 40 00 6a 00 ff ?? ?? ?? ?? ?? 68 54 40 40 00 e8 ?? ?? ?? ?? 59 50 68 54 40 40 00 e8 ?? ?? ?? ?? 59 59 68 90 01 00 00 ff ?? ?? ?? ?? ?? 68 6c 40 40 00 6a 00 6a 00 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 3d b7 00 00 00 75 ?? 6a 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 89 ?? ?? 68 34 41 40 00 ff ?? ?? e8 ?? ?? ?? ?? 59 59 85 c0 74 ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? a0 ?? ?? ?? ?? 88 ?? ?? 8d ?? ?? 50 e8 ?? ?? ?? ??}
		$hex2 = { 55 8b ec 81 ec 10 03 00 00 83 ?? ?? ?? ?? ?? ?? 68 04 01 00 00 8d ?? ?? ?? ?? ?? 50 6a 00 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 68 04 01 00 00 8d ?? ?? ?? ?? ?? 50 68 78 40 40 00 ff ?? ?? ?? ?? ?? 68 84 40 40 00 8d ?? ?? ?? ?? ?? 50 68 74 42 40 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 68 84 40 40 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 85 c0 0f ?? ?? ?? ?? ?? 6a 00 8d ?? ?? ?? ?? ?? 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 68 c0 42 40 00 68 01 00 00 80 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 50 8d ?? ?? ?? ?? ?? 50 6a 01 6a 00 68 94 40 40 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 6a 00 8d ?? ?? ?? ?? ?? 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 68 c0 42 40 00 68 02 00 00 80 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 50 8d ?? ?? ?? ?? ?? 50 6a 01 6a 00 68 94 40 40 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 6a 00 8d ?? ?? ?? ?? ?? 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 68 7c 42 40 00 68 02 00 00 80 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 50 8d ?? ?? ?? ?? ?? 50 6a 01 6a 00 68 94 40 40 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 68 34 41 40 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 0f b6 c0 85 c0 74 ?? 68 c8 00 00 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 6a 00 ff ?? ?? ?? ?? ?? 6a 00 ff ?? ?? ?? ?? ?? c9 c3}

	condition:
		(3 of them) or (any of ($hex*))
}rule WormSkypeMsgSpamerSample
{
	meta:
		Description  = "Worm.SkypeSpamer.sm"
		ThreatLevel  = "5"

	strings:
		$code = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC ?? ?? ?? ?? 53 55 56 57 33 DB 68 ?? ?? ?? ?? 88 5C 24 17 E8 ?? ?? ?? ?? 83 C4 04 85 C0 75 34 68 96 00 00 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 83 F8 01 75 10 E8 ?? ?? ?? ?? 3C 01 75 23 53 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
		$a = "Skype.exe" ascii wide
		$b = "msnmsgr.exe" ascii wide
	condition:
		2 of them
}