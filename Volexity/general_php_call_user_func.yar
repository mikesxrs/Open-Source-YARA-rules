rule general_php_call_user_func : General Webshells
{
    meta:
        author = "threatintel@volexity.com"
        description = "Webshells using call_user_func against an object from a file input or POST variable."
        date = "2021-06-16"
        hash1 = "40b053a2f3c8f47d252b960a9807b030b463ef793228b1670eda89f07b55b252"
        reference = "https://zhuanlan.zhihu.com/p/354906657"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $s1 = "@call_user_func(new C()" wide ascii

    condition:
        $s1
}
