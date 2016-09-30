rule AdwareSendoriSample
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
}