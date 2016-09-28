rule LONGRUN_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0)" wide ascii
                $s2 = "%s\\%c%c%c%c%c%c%c" wide ascii
                $s3 = "wait:" wide ascii
                $s4 = "Dcryption Error! Invalid Character" wide ascii

        condition:
                all of them
}