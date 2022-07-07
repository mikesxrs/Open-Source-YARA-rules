rule Mal_Infostealer_MSI_EXE_Jupyter_Certificate
{
    meta:
        description = "Detects Jupter by certificate"
        reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
        author = "BlackBerry Threat Research Team"
        date = "2021-11-04"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        // MSI Installer
        $msi = { D0 CF 11 E0 A1 B1 1A E1 }

        // MSI Strings
        $a1 = "EMCO MSI Package Builder"

        // PowerShell execution strings
        $b1 = "powershell-ExecutionPolicy bypass -command \"iex([\\[]IO.File[\\]]::ReadAllText('[CurrentUserProfileFolder]" nocase
        $b2 = "powershell-ep bypass -file \"[AppDataFolder]" nocase
        $b3 = /powershell-ep bypass -windowstyle hidden -command \"\$xp=\'\[AppDataFolder\].{0,256}\.{0,256}\'/ nocase
        $b4 = /powershell-ep bypass -windowstyle hidden -command \"\$p=\'\[AppDataFolder\].{0,256}\.{0,256}\'/ nocase
        $b5 = /powershell-ExecutionPolicy bypass -command \"iex\(\[\\\[\]IO.File\[\\\]\]::ReadAllText\(\'\[CurrentUserProfileFolder\].{1,256}\..{1,256}\'\)\)/ nocase

        // Certificate Name
        $c1 = "OOO ENDI"
        $c2 = "OOO MVS"
        $c3 = "OOO LEVELAP"
        $c4 = "Soto Manufacturing SRL"
        $c5 = "Decapolis Consulting Inc."

        // Co-signers
        $f1 = "SSL.com EV Root Certification Authority RSA R2"
        $f2 = "SSL.com EV Code Signing Intermediate CA RSA R3"
        $f3 = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
        $f4 = "DigiCert Trusted Root G40"

    condition:
        ($msi at 0 or uint16(0) == 0x5a4d) and
        all of ($a*) and
        1 of ($b*) and
        1 of ($c*) and
        2 of ($f*)
}
