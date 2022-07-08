rule webshell_java_realcmd : Commodity Webshells
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
        date = "2022-06-01"
        hash1 = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
        reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
        reference2 = "https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        $fn1 = "runCmd" wide ascii fullword
        $fn2 = "RealCMD" ascii wide fullword
        $fn3 = "buildJson" ascii wide fullword
        $fn4 = "Encrypt" ascii wide fullword

        $s1 = "AES/ECB/PKCS5Padding" ascii wide
        $s2 = "python -c 'import pty; pty.spawn" ascii wide
        $s3 = "status" ascii wide
        $s4 = "success" ascii wide
        $s5 = "sun.jnu.encoding" ascii wide
        $s6 = "java.util.Base64" ascii wide

    condition:
        all of ($fn*) or
        all of ($s*)
}
