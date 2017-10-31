rule executable_au3 : info compiler autit
{
    meta:
        // author = "@h3x2b <tracker _AT h3x.eu>"
        description = "Match AU3 autoit executables"

    strings:
        $str_au3_01 = "AU3"
        $str_au3_02 = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D }

    condition:
        all of them
}



rule vb_pcode : info compiler vb
{
    meta:
        // author = "@h3x2b <tracker _AT h3x.eu>"
        description = "VisualBasic compiled to P-Code bytecode"
        // http://waleedassar.blogspot.com/2012/03/visual-basic-malware-part-1.html

    strings:
        $str_vb_01 = "VB5"
        $str_vb_pcode = { E9 E9 E9 E9 CC CC CC CC CC CC CC CC CC CC CC CC 9E 9E 9E 9E }

    condition:
        ( $str_vb_01 )
        and $str_vb_pcode
}



rule vb_native: info compiler vb
{
    meta:
        // author = "@h3x2b <tracker _AT h3x.eu>"
        description = "VisualBasic compiled to Native code, http://waleedassar.blogspot.com/2012/03/visual-basic-malware-part-1.html"

    strings:
        $str_vb_01 = "VB5"
        $str_vb_ncode = { E9 E9 E9 E9 CC CC CC CC CC CC CC CC CC CC CC CC 55 8B EC }

    condition:
        ( $str_vb_01 )
        and $str_vb_ncode
}



rule dotnet_libraries: info compiler dotnet
{
    meta:
        // author = "@h3x2b <tracker _AT h3x.eu>"
        description = ".Net runtime mscoree.dll mscorwks.dll"

    strings:
        $str_dn_01 = "mscoree.dll"
        $str_dn_02 = "_CorExeMain"
        $str_dn_03 = "mscorwks.dll"
        $str_dn_04 = "CoInitializeEE"

    condition:
        2 of ($str_dn_* )

}
