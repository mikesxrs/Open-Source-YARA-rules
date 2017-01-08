rule elise{
    meta:
        author = "Brian Wallace @botnet_hunter"
        date = "2015-10-20"
        description = "Identify Elise"
    strings:
        $a1 = "Mozilla/4.0 (compatible; MSIE 8.0)" wide
        $a2 = "KERNEL32.DLL" wide
        $a3 = "Content-Length: 0" wide
        $a4 = "/%x/page_%02d%02d%02d%02d.html" wide

        $a5 = "%s=;expires=Thu, 01-Jan-1970 00:00:01 GMT"
        $a6 = "000ELISEA380.TMP"
    condition:
        all of them
}