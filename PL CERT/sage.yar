rule sage
{
    meta:
        author="msm"
		    reference = "https://www.cert.pl/en/news/single/sage-2-0-analysis/"

    strings:
        /* ransom message */
        $ransom1 = "ATTENTION! ALL YOUR FILES WERE ENCRYPTED!"
        $ransom2 = "SAGE 2.0 uses military grade elliptic curve cryptography and you"

        /* other strings */
        $str0 = "!Recovery_%s.html"
        $str1 = "/CREATE /TN \"%s\" /TR \"%s\" /SC ONLOGON /RL HIGHEST /F"

        /* code */
        $get_subdomain = {8B 0D ?? ?? 40 00 6A ?? [2] A1 ?? ?? 40 00 5? 5? 50 51 53 E8}
        $debug_file_name = {6A 00 6A 01 68 00 00 00 80 68 [4] FF 15 [4] 83 F8 FF}
        $get_request_subdomain = {74 ?? A1 [4] 5? 5? 68 ?? ?? 40 00 E8}
        $get_ec_pubkey = {68 [2] 40 00 68 [2] 40 00 E8 [4] 68 B9 0B 00 00 6A 08 E8}
        $get_extensions = { 8B 35 [2] 40 00 [0-3] 80 3E 00 74 24 }

    condition:
        all of ($ransom*) and any of ($str*)
        and any of ($get_subdomain, $debug_file_name, $get_request_subdomain, $get_ec_pubkey, $get_extensions)
}
