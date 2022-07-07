import "pe"

rule Mal_Infostealer_Win32_Jupyter_InfoStealer_Module
{
    meta:
        description = "Detects Jupter infostealer module"
        reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
        author = "BlackBerry Threat Research Team"
        date = "2021-11-08"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        $d1 = "WebRequest" nocase
        $d2 = "HttpWebRequest" nocase
        $d3 = "WebResponse" nocase
        $d4 = "GetResponseStream" nocase
        $d5 = "GetResponse" nocase
        $d6 = "IsInRole" nocase
        $d7 = "get_UTF8" nocase
        $d8 = "FromBase64String" nocase
        $d9 = "get_OSVersion" nocase
        $d10 = "GetFiles" nocase
        $d11 = "GetExtension" nocase
        $d12 = "get_Current" nocase
        $d13 = "GetEnumerator" nocase

        $j1 = { 6C 6F 67 69 6E 73 } // logins
        $j2 = { 43 00 6F 00 6F 00 6B 00 69 00 65 00 73 } // C.o.o.k.i.e.s
        $j3 = { 00 6C 00 6F 00 67 00 69 00 6E 00 73 00 2E 00 6A 00 73 00 6F 00 6E 00 } // .l.o.g.i.n.s...j.s.o.n.
        $j4 = { 00 63 00 6F 00 6F 00 6B 00 69 00 65 00 73 00 2E 00 73 00 71 00 6C 00 69 00 74 00 65 00 } // .c.o.o.k.i.e.s...s.q.l.i.t.e.

    condition:
        // DotNet
        pe.imports("mscoree.dll", "_CorDllMain") and
        12 of ($d*) and
        2 of ($j*)
}
