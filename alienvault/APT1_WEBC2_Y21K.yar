rule APT1_WEBC2_Y21K
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "Y29ubmVjdA" wide ascii // connect
        $2 = "c2xlZXA" wide ascii // sleep
        $3 = "cXVpdA" wide ascii // quit
        $4 = "Y21k" wide ascii // cmd
        $5 = "dW5zdXBwb3J0" wide ascii // unsupport
    condition:
        4 of them
}