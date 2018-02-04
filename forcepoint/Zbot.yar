rule crime_win_zbot_memory_dev_ws
{
    meta:
        description = "ZBot & variants - configuration _unpack routine detection"
        author = "Nick Griffin (Websense)"
        yaraexchange = "No distribution without author's consent"
        reference = "https://blogs.forcepoint.com/security-labs/crimeware-based-targeted-attacks-citadel-case-part-iii"
        date = "2014-04"
        filetype = "memory"
        md5 = "4d175203db0f269f9d86d2677ac859cf"
        sha1 = "4b422b48be4beaa44557c452f0920aa1ee0b16cb"
     
    strings:
        $hex_string = {85 C0 7? ?? 8A 4C 30 FF 30 0C 30 48 7?}
        $bkrebs = "Coded by BRIAN KREBS for personal use only. I love my job & wife."
     
    condition:
        $hex_string or $bkrebs
} 
