rule andromeda
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-03-13"
        description = "Identify Andromeda"
    strings:
        $config = {1c 1c 1d 03 49 47 46}
        $c1 = "hsk\\ehs\\dihviceh\\serhlsethntrohntcohurrehem\\chsyst"
    condition:
        all of them
}