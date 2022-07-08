rule qbot_vbs
{
    meta:
        description = "Catches QBot VBS files"
        reference = "https://research.checkpoint.com/2020/exploring-qbots-latest-attack-methods/"
        author = "Alex Ilgayev"
        date = "2020-06-07"
    strings:
        $s3 = "ms.Send"
        $s4 = "for i=1 to 6"
        $s5 = "if ms.readyState = 4 Then"
        $s6 = "if len(ms.responseBody) <> 0 then"
        $s7 = /if left\(ms.responseText, \w*?\) = \"MZ\" then/
    condition:
        filesize > 20MB and $s3 and $s4 and $s5 and $s6 and $s7
}
