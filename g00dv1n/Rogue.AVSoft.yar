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
