import "pe"
rule ducktail_exceldna_packed
{
    meta:
        author="WithSecure"
        description="Detects Excel Add-in variants of DUCKTAIL malware"
        date="2022-11-17"
        version="1.0"
        reference="https://labs.withsecure.com/publications/ducktail_returns"
        hash1="e11b55bea4cd63d09220eaf72ffb591838ac54fb"
        hash2="630f467fda3ac80eaa2f23b141aff122f501504e"
        hash3="2a3a7682e9e77b3124a09dff0167fffe9d91c8b7"
        report = "https://www.withsecure.com/en/expertise/research-and-innovation/research/ducktail-an-infostealer-malware"
    strings:
        $xll_str_1 = "exceldna" nocase ascii
        $xll_str_2 = "iexceladdin" nocase ascii
        $encryption_str_1 = "zbase32" nocase ascii
        $encryption_str_2 = "sharpaescrypt" nocase ascii
        $encryption_str_3 = "confuserex" nocase ascii
        $dt_module_name = "exceladdinbuilder" nocase ascii
     condition:
        uint16(0) == 0x5A4D
        and any of ($xll_str_*)
        and (2 of ($encryption_str_*)
             or for any res in pe.resources : ( res.name_string == "C\x00O\x00N\x00F\x00I\x00G\x00" and hash.sha256(res.offset, res.length) == "08515030bb98ffd03fcbf15788e49d155a59cdbc74be27066542e8c0e29214f9")
             or $dt_module_name
        )
}