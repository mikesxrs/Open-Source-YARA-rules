rule NanoCore
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-03-27"
        description = "Identify NanoCore"
    strings:
        $s1 = "nanocore" nocase
        $s2 = "clientplugin" nocase
        $s3 = "projectdata" nocase
        $s4 = "logclientmessage" nocase
    condition:
        all of them
}
