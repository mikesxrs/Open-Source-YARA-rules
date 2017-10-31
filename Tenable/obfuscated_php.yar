rule eval_statement
{
    meta:
        description = "Obfuscated PHP eval statements"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "9da32d35a28d2f8481a4e3263e2f0bb3836b6aebeacf53cd37f2fe24a769ff52"
        hash = "8c1115d866f9f645788f3689dff9a5bacfbee1df51058b4161819c750cf7c4a1"
        hash = "14083cf438605d38a206be33542c7a4d48fb67c8ca0cfc165fa5f279a6d55361"

    strings:
        $obf = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/

    condition:
        all of them
}

rule hardcoded_urldecode
{
    meta:
        description = "PHP with hard coded urldecode call"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "79b22d7dbf49d8cfdc564936c8a6a1e2"
        hash = "38dc8383da0859dca82cf0c943dbf16d"

    strings:
        $obf = /urldecode[\t ]*\([\t ]*'(%[0-9a-fA-F][0-9a-fA-F])+'[\t ]*\)/

    condition:
        all of them
}

rule chr_obfuscation
{
    meta:
        description = "PHP with string building using hard coded values in chr()"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "d771409e152d0fabae45ea192076d45e"
        hash = "543624bec87272974384c8ab77f2357a"
        hash = "cf2ab009cbd2576a806bfefb74906fdf"

    strings:
        $obf = /\$[^=]+=[\t ]*(chr\([0-9]+\)\.?){2,}/

    condition:
        all of them
}
