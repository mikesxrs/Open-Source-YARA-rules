rule Mal_Infostealer_MSI_Jupyter_Embedded_PowerShell
{
    meta:
        description = "Detects Jupter by a specific PowerShell command present in the MSI Installer"
        reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
        author = "BlackBerry Threat Research Team"
        date = "2021-10-14"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        // MSI Installer
        $msi = { D0 CF 11 E0 A1 B1 1A E1 }

        // Embedded PowerShell Command
        $x1 = /powershell-ep bypass -windowstyle hidden -command \"\$xp=\'\[AppDataFolder\]pd\w*\.(log|txt)\';\$xk=\'[a-zA-Z]{52}\';\$xb=\[\\\[\]System\.Convert\[\\\]\]::FromBase64String\(\[\\\[\]System\.IO\.File\[\\\]\]::ReadAllText\(\$xp\)\);remove-item \$xp;for\(\$i=0;\$i -lt \$xb.count;\)\[\\\{\]for\(\$j=0;\$j -lt \$xk\.length;\$j\+\+\)\[\\\{\]\$xb\[\\\[\]\$i\[\\\]\]=\$xb\[\\\[\]\$i\[\\\]\] -bxor \$xk\[\\\[\]\$j\[\\\]\];\$i\+\+;if\(\$i -ge \$xb.count\)\[\\\{\]\$j=\$xk\.length;\[\\\}\]\[\\\}\]\[\\\}\];\$xb=\[\\\[\]System.Text.Encoding\[\\\]\]::UTF8\.GetString\(\$xb\);iex \$xb;/ nocase

    condition:
        $msi at 0 and
        all of ($x*)
}
