rule webshell_php_icescorpion : Commodity Webshell
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the IceScorpion webshell."
        date = "2022-01-17"
        hash1 = "5af4788d1a61009361b37e8db65deecbfea595ef99c3cf920d33d9165b794972"
        reference = "https://www.codenong.com/cs106064226/"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $s1 = "[$i+1&15];"
        $s2 = "openssl_decrypt"

    condition:
        all of them and 
        filesize < 10KB
}
