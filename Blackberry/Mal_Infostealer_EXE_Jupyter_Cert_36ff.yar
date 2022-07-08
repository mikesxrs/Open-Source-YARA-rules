import "pe"

rule Mal_Infostealer_EXE_Jupyter_Cert_36ff
{
    meta:
        description = "Detects Jupter executables by certificate OOO Sistema (36ff)"
        reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
        author = "BlackBerry Research & Intelligence Team"
        date = "2021-10-14"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"       

    condition:
        uint16(0) == 0x5a4d and
        for any i in (0 .. pe.number_of_signatures) : (
            pe.signatures[i].issuer contains "Certum Extended Validation Code Signing CA SHA2" and
            pe.signatures[i].serial == "36:ff:67:4e:b3:05:e9:9c:35:56:5f:a3:01:d5:c4:b0" // Serial variable must be lowercase
            )
}
