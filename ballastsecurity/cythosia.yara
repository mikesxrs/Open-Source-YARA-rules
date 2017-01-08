rule Cythosia{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-03-21"
        description = "Identify Cythosia"
    strings:
        $str1 = "HarvesterSocksBot.Properties.Resources" wide
    condition:
        all of them
}