rule AdwareWebWatcherSample
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
}