rule AcridRain
{
    meta:
        description = "Rule to detect AcridRain malware"
        author = "Stormshield"
        reference = "https://thisissecurity.stormshield.com/2018/08/28/acridrain-stealer/"

    strings:
        $mz = { 4d 5a }
        // old sample
        $old_amigo = "_________________________________AMIGO_________________________________" ascii wide
        $old_google_chrome = "_________________________________GOOGLE CHROME_________________________________" ascii wide
        $old_vivaldi = "_________________________________Vivaldi_________________________________" ascii wide
        $old_orbitum = "_________________________________Orbitum_________________________________" ascii wide
        $old_epic = "_________________________________Epic Privacy Browser_________________________________" ascii wide
        $old_cyberfox = "_________________________________Cyberfox_________________________________" ascii wide
        // new sample
        $new_epic_3 = "%s\\\\Epic Privacy Browser\\\\User Data\\\\Profile 3" ascii wide
        $new_epic_2 = "%s\\\\Epic Privacy Browser\\\\User Data\\\\Profile 2" ascii wide
        $new_epic_1 = "%s\\\\Epic Privacy Browser\\\\User Data\\\\Profile 1" ascii wide
        $new_spotnik_CC = "Sputnik_CC.txt" ascii wide
        $new_coccoc_cookies = "CocCoc_Cookies.txt" ascii wide
        $new_rambler = "rambler.txt" ascii wide
        //zip
        $zip_32_zip = "32.zip" ascii wide
        $zip_opana_zip = "opana.zip" ascii wide
        $zip_libs_zip = "Libs.zip" ascii wide
        //all
        $all_templogik = "templogik" ascii wide
        $all_templogim = "templogim" ascii wide
        $all_templogin = "templogin" ascii wide

    condition:
        ($mz at 0) and (3 of ($old_*) or 3 of ($new_*)) and (2 of ($zip_*)) and (2 of ($all_*))
}
