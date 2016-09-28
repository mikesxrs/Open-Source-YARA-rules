rule HACKSFASE2_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Send to Server failed." wide ascii
                $s2 = "HandShake with the server failed. Error:" wide ascii
                $s3 = "Decryption Failed. Context Expired." wide ascii

        condition:
                all of them
}