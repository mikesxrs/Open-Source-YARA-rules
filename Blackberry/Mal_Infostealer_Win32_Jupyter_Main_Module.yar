import "pe"

rule Mal_Infostealer_Win32_Jupyter_Main_Module
{
    meta:
        description = "Detects Jupter main module"
        reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
        author = "BlackBerry Threat Research Team"
        date = "2021-11-23"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        $g1 = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 } // h.t.t.p.:././.
        $g2 = { 5C 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 5C 00 52 00 4F 00 41 00 4D 00 49 00 4E 00 47 } // \.A.P.P.D.A.T.A.\.R.O.A.M.I.N.G
        $g3 = { 63 00 68 00 61 00 6E 00 67 00 65 00 5F 00 73 00 74 00 61 00 74 00 75 00 73 } // c.h.a.n.g.e._.s.t.a.t.u.s
        $g4 = { 50 00 4F 00 53 00 54 } // P.O.S.T
        $g5 = { 69 00 73 00 5F 00 73 00 75 00 63 00 63 00 65 00 73 00 73 } // i.s._.s.u.c.c.e.s.s
        $g6 = { 75 00 73 00 65 00 72 00 70 00 72 00 6F 00 66 00 69 00 6C 00 65 } // u.s.e.r.p.r.o.f.i.l.e
        $g7 = { 44 00 45 00 53 00 4B 00 54 00 4F 00 50 00 2D } // D.E.S.K.T.O.P.-
        $g8 = { 4C 00 41 00 50 00 54 00 4F 00 50 00 2D } // L.A.P.T.O.P.-
        $g9 = { 78 00 38 00 36} // x.8.6
        $g10 = { 78 00 36 00 34 } // x.6.4
        $g11 = { 41 00 64 00 6D 00 69 00 6E } // A.d.m.i.n
        $g12 = { 56 00 69 00 73 00 74 00 61 } // V.i.s.t.a
        $g13 = { 64 00 6E 00 73 } // d.n.s
        $g14 = { 64 00 7A 00 6B 00 61 00 62 72 } // d.z.k.a.b.r
        $g15 = { 78 00 7A 00 6B 00 61 00 62 00 73 00 72 } // x.z.k.a.b.s.r
        $g16 = { 64 00 7A 00 6B 00 61 00 62 00 73 00 72 } // d.z.k.a.b.s.r

        // Version Strings
        $h1 = { 4F 00 43 00 2D } // O.C.-
        $h2 = { 4E 00 56 00 2D } // N.V.-
        $h3 = { 53 00 50 00 2D } // S.P.-
        $h4 = { 49 00 4E 00 2D } // I.N.-

        $i = "System.Net"

    condition:
        10 of ($g*) and
        1 of ($h*) and
        (pe.imports("mscoree.dll", "_CorDllMain") or $i) // DotNet
}
