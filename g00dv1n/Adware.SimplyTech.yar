rule SimplyTechSample
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
}