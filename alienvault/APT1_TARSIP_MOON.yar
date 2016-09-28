rule APT1_TARSIP_MOON
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $s1 = "\\XiaoME\\SunCloud-Code\\moon" wide ascii
        $s2 = "URL download success!" wide ascii
        $s3 = "Kugoosoft" wide ascii
        $msg1 = "Modify file failed!! So strange!" wide ascii
        $msg2 = "Create cmd process failed!" wide ascii
        $msg3 = "The command has not been implemented!" wide ascii
        $msg4 = "Runas success!" wide ascii
        $onec1 = "onec.php" wide ascii
        $onec2 = "/bin/onec" wide ascii
    condition:
        1 of ($s*) and 1 of ($msg*) and 1 of ($onec*)
}