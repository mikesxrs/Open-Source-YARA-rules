rule webshell_java_behinder_shellservice : Webshells Commodity
{
    meta:
        author = "threatintel@volexity.com"
        description = "Looks for artifacts generated (generally seen in .class files) related to the Behinder framework."
        date = "2022-03-18"
        hash1 = "9a9882f9082a506ed0fc4ddaedd50570c5762deadcaf789ac81ecdbb8cf6eff2"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        reference = "https://github.com/MountCloud/BehinderClientSource/blob/master/src/main/java/net/rebeyond/behinder/core/ShellService.java"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        memory_suitable = 1

    strings:
        $s1 = "CONNECT" ascii fullword
        $s2 = "DISCONNECT" ascii fullword
        $s3 = "socket_" ascii fullword
        $s4 = "targetIP" ascii fullword
        $s5 = "targetPort" ascii fullword
        $s6 = "socketHash" ascii fullword
        $s7 = "extraData" ascii fullword

    condition:
        all of them
}
