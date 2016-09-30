rule RootkitSampleDriverAgony
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
}