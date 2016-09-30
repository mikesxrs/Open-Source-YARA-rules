rule BladabindiASample
{
    meta:
        Description = "Backdoor.Bladabindi.A.vb"
        ThreatLevel = "5"

    strings:
        $ = "shutdown -r -t 00" ascii wide
        $ = "netsh firewall add allowedprogram" ascii wide
        $ = "netsh firewall delete allowedprogram" ascii wide
        $ = "cmd.exe /k ping 0 & del" ascii wide
        $ = "ReceiveBufferSize" ascii wide
        $ = "SendBufferSize" ascii wide
        $ = "restartcomputer" ascii wide
        $ = "NoWindowsUpdate" ascii wide
        $ = "winupdateoff" ascii wide
        $ = "DisableTaskMgr" ascii wide
        $ = "set cdaudio door closed" ascii wide
        $ = "set cdaudio door open" ascii wide
        $ = "VMDragDetectWndClass" ascii wide
        $ = "%dark%" ascii wide
        $ = "microwaveone.ddns.net" ascii wide

    condition:
        5 of them
}