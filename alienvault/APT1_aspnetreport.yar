rule APT1_aspnetreport
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $url = "aspnet_client/report.asp" wide ascii
        $param = "name=%s&Gender=%c&Random=%04d&SessionKey=%s" wide ascii
    condition:
        $url and $param and APT1_payloads
}