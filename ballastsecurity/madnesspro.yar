rule madnesspro_strings
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-03-13"
        description = "Identify Madness Pro"
    strings:
        $c = "YXBvS0FMaXBsaXM9"
        $str5 = "d3Rm" fullword
        $str6 = "ZXhl" fullword
        $string0 = "Referer: "
        $string1 = "regini "
        $string2 = "GetAtomNameA (atom, s, sizeof(s)) "
        $string3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        $string4 = "dmVyPQ"
        $string5 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cRXhwbG9yZXJcU2hlbGwgRm9sZGVycw"
        $string6 = "U1lTVEVNXENvbnRyb2xTZXQwMDJcc2VydmljZXNcU2hhcmVkQWNjZXNzXFBhcmFtZXRlcnNcRmlyZXdhbGxQb2xpY3lcU3RhbmRh"
        $string7 = "Oio6RW5hYmxlZDo"
        $string8 = "TW96aWxsYS80LjAgKFdpbmRvd3M7IFU7IFdpbmRvd3MgTlQgNi4xOyBubDsgcnY6MS45LjIuMykgR2Vja28vMjAxMDA0MDEgRmly"
        $string9 = "Q2hlY2tUb2tlbk1lbWJlcnNoaXA"
        $string10 = "R0g1Sy1HS0w4LUNQUDQtREUyNA"
        $string11 = "cookie"
        $string12 = "U1lTVEVNXENvbnRyb2xTZXQwMDNcc2VydmljZXNcU2hhcmVkQWNjZXNzXFBhcmFtZXRlcnNcRmlyZXdhbGxQb2xpY3lcU3RhbmRh"
        $string13 = "Content-Type: application/x-www-form-urlencoded"
        $string14 = "Internet Explorer"
        $string15 = "U1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XFNlcnZpY2VzXFNoYXJlZEFjY2Vzc1xQYXJhbWV0ZXJzXEZpcmV3YWxsUG9saWN5XFN0"
        $string16 = "U1lTVEVNXENvbnRyb2xTZXQwMDFcc2VydmljZXNcU2hhcmVkQWNjZXNzXFBhcmFtZXRlcnNcRmlyZXdhbGxQb2xpY3lcU3RhbmRh"
    condition:
        all of them
}
