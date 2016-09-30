rule SearchProtectSample
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
}