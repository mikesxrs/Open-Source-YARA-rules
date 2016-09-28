rule NEWSREELS_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0)" wide ascii
                $s2 = "name=%s&userid=%04d&other=%c%s" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "command is null!" wide ascii
                $s5 = "noclient" wide ascii
                $s6 = "wait" wide ascii
                $s7 = "active" wide ascii
                $s8 = "hello" wide ascii


        condition:
                all of them
}