rule webshell_aspx_reGeorgTunnel : Webshell Commodity
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "variation on reGeorgtunnel"
        hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
        reference2 = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"

    strings:
        $s1 = "System.Net.Sockets"
        $s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
        $t1 = ".Split('|')"
        $t2 = "Request.Headers.Get"
        $t3 = ".Substring("
        $t4 = "new Socket("
        $t5 = "IPAddress ip;"

    condition:
        all of ($s*) or
        all of ($t*)
}
