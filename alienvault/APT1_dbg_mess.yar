rule APT1_dbg_mess
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $dbg1 = "Down file ok!" wide ascii
        $dbg2 = "Send file ok!" wide ascii
        $dbg3 = "Command Error!" wide ascii
        $dbg4 = "Pls choose target first!" wide ascii
        $dbg5 = "Alert!" wide ascii
        $dbg6 = "Pls press enter to make sure!" wide ascii
        $dbg7 = "Are you sure to " wide ascii
    condition:
        4 of them and APT1_payloads
}