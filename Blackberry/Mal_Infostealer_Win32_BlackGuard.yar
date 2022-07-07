import "pe"

rule Mal_Infostealer_Win32_BlackGuard
{
    meta:
        description = "Detects W32 BlackGuard Infostealer"
        author = "BlackBerry Threat Research team "
        reference = "https://blogs.blackberry.com/en/2022/04/threat-thursday-blackguard-infostealer"
        date = "2022-14-04"
        sha256 = "6AB3B21FA7CB638ED68509BE1ED6302284E8A9CD1A10F9B6837C057154AA6162"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        $a1 = { 06 91 06 61 20 AA 00 00 00 61 D2 9C 06 17 58 0A }
        $a2 = "System.Data.SQLite"
        $a3 = "FromBase64String"
        $a4 = "BlockInput"
        $a5 = "UploadFile"
        $a6 = "Passwords"
        $a7 = "Discord"
        $a8 = "GetVolumeInformationA"
        $a9 = "NordVPN"
        $a10 = "OpenVPN"
        $a11 = "ProtonVPN"
        $a12 = "OperaCookies"
        $a13 = "EdgeCookies"
        $a14 = "ChromeCookies"

        $b1 = "upche" wide

    condition:
        uint16(0) == 0x5a4d and
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and
        pe.number_of_sections == 3 and
        pe.section_index(".text") == 0 and
        pe.section_index(".rsrc") == 1 and
        pe.section_index(".reloc") == 2 and
        ((all of ($a*)) or ((12 of ($a*) and all of ($b*))))
}
