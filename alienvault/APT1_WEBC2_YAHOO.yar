rule APT1_WEBC2_YAHOO
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $http1 = "HTTP/1.0" wide ascii
        $http2 = "Content-Type:" wide ascii
        $uagent = "IPHONE8.5(host:%s,ip:%s)" wide ascii
    condition:
        all of them
}