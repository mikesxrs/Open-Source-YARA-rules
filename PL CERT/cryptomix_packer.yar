rule cryptomix_packer
{
    meta:
         author     = "msm"
		 reference = "https://www.cert.pl/en/news/single/technical-analysis-of-cryptomixcryptfile2-ransomware/"

    strings:
       $old_real_main = {8B [5] 8B [5] 03 ?? 89 ?? FC FF 55 FC}
       $old_crypto_ops = {83 ?? 1F 83 ?? 60}
       $old_crypto_xor = {8A 90 [4] 30 14 0E}  // extract xor key from this

       $new_crypto_ops = {03 85 [4] 88 10 EB ??}
       $new_crypto_xor = {A1 [4] 89 45 ??}  // extract xor key from this

    condition:
       2 of them
}
