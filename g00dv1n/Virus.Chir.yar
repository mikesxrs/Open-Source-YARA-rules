rule ChirBSample
{
    meta:
        Description = "Virus.Chir.B.vb"
        ThreatLevel = "5"

    strings:
        $ = "runouce.exe" ascii wide
        $ = "imissyou@btamail.net.cn" ascii wide
        $ = "ChineseHacker-2" ascii wide

    condition:
        all of them
}