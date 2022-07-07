rule trojan_win_xe_backwash : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "The BACKWASH malware family, which acts as a reverse shell on the victim machine."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        hash = "815d262d38a26d5695606d03d5a1a49b9c00915ead1d8a2c04eb47846100e93f"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $pdb1 = "x:\\MultiOS_ReverseShell-master\\Multi-OS_ReverseShell\\obj\\Release\\XEReverseShell.pdb"
        $pdb2 = "\\Release\\XEReverseShell.pdb"

        $a1 = "RunServer" ascii
        $a2 = "writeShell" ascii
        $a3 = "GetIP" ascii

        $b1 = "xequit" wide
        $b2 = "setshell" wide

    condition:
        any of ($pdb*) or
        (
            (
                all of ($a*) or 
                all of ($b*)
            ) and     
            filesize < 40KB 
        )
}

