rule BackdoorGenASample
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
}