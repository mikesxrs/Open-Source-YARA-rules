rule evora {
    meta:
        author = "Brian Wallace @botnet_hunter"
        date = "2015-10-20"
        description = "Identify Evora"
    strings:
        $a1 = "{A872638D-DC2B9B23}"
        $a2 = "Mozilla/4.0 (compatible; MSIE 8.0)" wide
        $a3 = "/%x/thread_%02d%02d%02d%02d.html" wide
        $a4 = "F95F6E38" wide

        $b1 = "{A872638D-DC2B9B23}"
        $b2 = "{F40150C7-B623-41bc-8693-0445343A3A69}" wide
        $b3 = "Global\\%d" wide
    condition:
        all of ($a*) or all of ($b*)
}