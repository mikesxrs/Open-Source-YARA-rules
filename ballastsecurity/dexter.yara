rule dexter_strings
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-09-10"
        description = "Identify Dexter POSGrabber"
    strings:
        $s1 = "UpdateMutex:"
        $s2 = "response="
        $s3 = "page="
        $s4 = "scanin:"
    condition:
        all of them
}