rule Andromeda
{
    meta:
        desc = "Andromeda dropper"
        family = "Andromeda"
        author = "OpenAnalysis.net"

    strings:
        $a1 = "Referer: https://www.bing.com/"
        $a2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"
        $a3 = "/last.so"
        $a4 = "30f5877bda910f27840f2e21461723f1"
        $a5 = "Global\\msiff0x1"


    condition:
        $a5 or ($a1 and $a2 and $a3) or ($a2 and $a4) or ($a1 and $a4)
}
