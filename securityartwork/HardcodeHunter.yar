rule HardcodeHunter
{
        meta:
                description = "Veil Hardcoded IP"
                reference = "https://www.securityartwork.es/2015/03/20/deteccion-de-codigo-malicioso-con-yara-i/"
        strings:
                $ IP = / (25 [0-5] | 2 [0-4] [0-9] | [01]? [0-9] [0-9]?) \.
                      (25 [0-5] | 2 [0-4] [0-9] | [01]? [0-9] [0-9]?) \.
                      (25 [0-5] | 2 [0-4] [0-9] | [01]? [0-9] [0-9]?) \.
                      (25 [0-5] | 2 [0-4] [0-9] | [01]? [0-9] [0-9]?) /
        condition:
                $ IP at 0x28df
}
