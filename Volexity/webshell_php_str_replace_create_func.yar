rule webshell_php_str_replace_create_func : Webshells General
{
    meta:
        author = "threatintel@volexity.com"
        description = "Looks for obfuscated PHP shells where create_function() is obfuscated using str_replace and then called using no arguments."
        reference = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        date = "2022-04-04"
        hash1 = "c713d13af95f2fe823d219d1061ec83835bf0281240fba189f212e7da0d94937"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $php = "<?php"
        // $P=str_replace(
        $s = "=str_replace(" ascii
        // call it as a function
        // $S=$P('',$a);
        $anon_func = "(''," ascii
        
    condition:
        filesize < 100KB and 
        $php at 0 and
        for any i in (1..#s):
            (
                for any j in (1..#anon_func):
                    (
					    uint16be(@s[i]-2) == uint16be(@anon_func[j]-2)
					)
            )
}
