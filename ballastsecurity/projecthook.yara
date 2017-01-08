rule ProjectHook
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-09"
        description = "Identify ProjectHook"
    strings:
        $projecthook = "ProjectHook"
        $delphi = "FastMM Borland Edition (c) 2004 - 2008 Pierre le Riche / Professional Software Development"
    condition:
        all of them
}