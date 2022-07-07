rule Mal_Infostealer_PowerShell_Jupyter_Updated_Samples
{
    meta:
        description = "Detects Jupter powershell via common strings"
        reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
        author = "BlackBerry Threat Research Team"
        date = "2021-11-04"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        $c1 = /\.[T|t][O|o][L|l][O|o][W|w][E|e][R|r]\(\)\)?;[I|i][E|e][X|x]/
        $c2 = "get-random -minimum 50000 -maximum 200000" nocase
        $c3 = "ReaDALlBYTES" nocase
        $c4 = /createshortcut\(\$env\:appdata\+'\\m\'\+\'icr\'\+\'oso\'\+\'ft\'\+\'\\w\'\+\'ind\'\+\'ow\'\+\'s\\\'\+\'st\'\+\'art\'\+\' me\'\+\'nu\'\+\'\\pr\'\+\'ogr\'\+\'ams\\\'\+\'st\'\+\'art\'\+\'up\'\+\'\\.{29}\.lnk\'\)/ nocase

    condition:
        all of ($c*)
}
