rule AdwareSolimbdaSample
{
    meta:
        Description = "Adware.Solimbda.vb"
        ThreatLevel = "5"

    strings:
		$ = "http://api.downloadmr.com" ascii wide
		$ = "SuggestedApps" ascii wide

    condition:
        all of them
}