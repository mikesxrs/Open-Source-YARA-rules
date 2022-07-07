rule general_java_encoding_and_classloader : Webshells General
{
    meta:
        author = "threatintel@volexity.com"
        description = "Identifies suspicious java-based files which have all the ingredients required for a webshell."
        reference = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        date = "2022-04-07"
        hash1 = "0d5dc54ef77bc18c4c5582dca4619905605668cffcccc3829e43c6d3e14ef216"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $s1 = "javax.crypto.spec.SecretKeySpec" ascii
        $s2 = "java/security/SecureClassLoader" ascii
        $s3 = "sun.misc.BASE64Decoder" ascii

    condition:
        filesize < 50KB and
        all of them
}
