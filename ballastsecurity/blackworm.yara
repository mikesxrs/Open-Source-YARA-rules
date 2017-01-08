rule BlackWorm{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-05-20"
        description = "Identify BlackWorm"
    strings:
        $str1 = "m_ComputerObjectProvider"
        $str2 = "MyWebServices"
        $str3 = "get_ExecutablePath"
        $str4 = "get_WebServices"
        $str5 = "My.WebServices"
        $str6 = "My.User"
        $str7 = "m_UserObjectProvider"
        $str8 = "DelegateCallback"
        $str9 = "TargetMethod"
        $str10 = "000004b0" wide
        $str11 = "Microsoft Corporation" wide
    condition:
        all of them
}