rule apt_win_gimmick_dotnet_base : StormCloud
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the base version of GIMMICK in .NET."
        reference = "https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/"
        date = "2020-03-16"
        hash1 = "b554bfe4c2da7d0ac42d1b4f28f4aae854331fd6d2b3af22af961f6919740234"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 1

    strings:
        $other1 = "srcStr is null" wide 
        $other2 = "srcBs is null " wide 
        $other3 = "Key cannot be null" wide 
        $other4 = "Faild to get target constructor, targetType=" wide 
        $other5 = "hexMoudule(public key) cannot be null or empty." wide 
        $other6 = "https://oauth2.googleapis.com/token" wide 

        $magic1 = "TWljcm9zb2Z0IUAjJCVeJiooKQ==" ascii wide
        $magic2 = "DAE47700E8CF3DAB0@" ascii wide 

    condition:
        5 of ($other*) or 
        any of ($magic*)
}
