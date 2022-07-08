rule general_php_fileinput_eval : Webshells General
{
    meta:
        author = "threatintel@volexity.com"
        description = "Look for PHP files which use file_get_contents and then shortly afterwards use an eval statement."
        reference = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        date = "2021-06-16"
        hash1 = "1a34c43611ee310c16acc383c10a7b8b41578c19ee85716b14ac5adbf0a13bd5"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $s1 = "file_get_contents(\"php://input\");"
        $s2 = "eval("

    condition:
        $s2 in (@s1[1]..@s1[1]+512)
}
