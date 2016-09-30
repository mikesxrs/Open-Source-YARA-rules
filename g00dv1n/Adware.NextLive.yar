rule NextLiveSample
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
}