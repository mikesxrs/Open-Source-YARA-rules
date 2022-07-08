import "pe"
import "dotnet"

rule Mal_Infostealer_Win32_Jupyter_Download_and_Execute_Module
{
    meta:
        description = "Detects Jupter download and execute module. Research has shown it downloading SolarDelphi / JupyterStealer."
        reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
        author = "BlackBerry Threat Research Team"
        date = "2021-11-09"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        $e1 = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 }
        $e2 = { 47 00 45 00 54 00 00 3D 63 00 3A 00 5C 00 77 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 73 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 77 00 69 00 6E 00 76 00 65 00 72 00 2E 00 65 00 78 00 65 }
        $e3 = { 00 2F 00 67 00 65 00 74 00 2F 00 }
        $e4 = "FromBase64String"
        $e5 = "get_UTF8"
        $e6 = "WebResponse"
        $e7 = "GetResponse"
        $e8 = "Invoke"

    condition:
        // DotNet
        pe.imports("mscoree.dll", "_CorDllMain") and
        dotnet.version == "v4.0.30319" and
        dotnet.assembly.version.major == 0 and
        dotnet.assembly.version.minor == 0 and
        all of ($e*)
}
