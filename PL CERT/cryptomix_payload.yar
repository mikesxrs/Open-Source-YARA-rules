rule cryptomix_payload
{
    meta:
         author     = "msm"
		 reference = "https://www.cert.pl/en/news/single/technical-analysis-of-cryptomixcryptfile2-ransomware/"

    strings:
        $get_static_rsa = { 56 68 [4] E8 [4] 59 59 }
        $get_final_message = { B9 ?? ?? 00 00 BE [4] 8D BD [4] [0-10] F3 A5}
        $get_email_format = { FF 75 ?? 68 [4] 50 FF 55 }
        $get_rsa_reg_key = { 6A 00 68 [4] 68 01 00 00 80 FF D0 68  }
        $get_extension = { 68 3C 72 40 00 8D 4C ?? ?? 51 FF D0 }
        $get_extensions_to_encrypt = { FF 74 24 [1] 68 [4] E8 }
        $get_extensions_to_encrypt_new = { 68 [4] BE [4] 56 FF D0 85 C0 }
        $get_cnc_url = { 68 [4] E8 [4] 48 F7 D8 1B C0 40 }

    condition:
       3 of ($get_*)
}
