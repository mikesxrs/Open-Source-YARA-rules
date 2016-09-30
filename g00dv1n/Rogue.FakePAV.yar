rule RogueFakePAVSample
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
}