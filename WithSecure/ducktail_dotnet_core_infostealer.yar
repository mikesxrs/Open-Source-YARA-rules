rule ducktail_dotnet_core_infostealer  
{
    meta:
        author="WithSecure"
        description="Detects DUCKTAIL malware written in .NET Core"
        date="2022-07-18"
        version="1.0"
        reference="https://labs.withsecure.com/publications/ducktail"
        hash1="b260f3857990e11fa267d3f1cad4c9bed59a9d4b"
        hash2="db74863c01817bf4eba39cd8a0ebbce9bda85a37"
        hash3="3a4b395301f61b7e6afc0ab27dc02331455181d0"
        report = "https://www.withsecure.com/en/expertise/research-and-innovation/research/ducktail-an-infostealer-malware"
    strings:
        $dotnet_core_bundle_signature = { 8B 12 02 B9 6A 61 20 38 72 7B 93 02 14 D7 A0 32 13 F5 B9 E6 EF AE 33 18 EE 3B 2D CE 24 B3 6A AE }
        // Facebook-related
        $fb_str_1 = "c_user" wide ascii
        $fb_str_2 = "https://business.facebook.com/security/twofactor/reauth/enter" wide ascii
        $fb_str_3 = "https://business.facebook.com/security/twofactor/reauth" wide ascii
        $fb_str_4 = "mbasic.facebook.com" wide ascii
        $fb_str_5 = "DTSGInitData\",[],{\"token\":\"" wide ascii
        $fb_str_6 = "www.facebook.com" wide ascii
        $fb_str_7 = "m.facebook.com" wide ascii
        $fb_str_8 = "business.facebook.com" wide ascii
        $fb_str_9 = "approvals_code=" wide ascii
        $fb_str_10 = "c_user=" wide ascii
        $fb_str_11 = "&__a=1&__comet_req=0&fb_dtsg=" wide ascii
        $fb_str_12 = "&__jssesw=1" wide ascii
        $fb_str_13 = "approvals_code=" wide ascii
        $fb_str_14 = "<BmLinks>k__BackingField" wide ascii
        $fb_str_15 = "set_FbCookies" wide ascii
        $fb_str_16 = "<AdsAccount>k__BackingField" wide ascii
        $fb_str_17 = "GetAllFbData" wide ascii
        $fb_str_18 = "get_account_id" wide ascii
        $fb_str_19 = "set_BmLinks" wide ascii
        $fb_str_20 = "GetBmLink" wide ascii
        $fb_str_21 = "GetBm" wide ascii
        $fb_str_22 = "ExtractUserId" wide ascii
        $fb_str_23 = "set_Bussinesses" wide ascii
        $fb_str_24 = "set_FbData" wide ascii
        $fb_str_25 = "get_Nguong" wide ascii
        $fb_str_26 = "ResetCookie" wide ascii
        $fb_str_27 = "set_UserId" wide ascii
        $fb_str_28 = "<Nguong>k__BackingField" wide ascii
        $fb_str_29 = "get_UserId" wide ascii
        $fb_str_30 = "set_Nguong" wide ascii
        $fb_str_31 = "AdsBusiness" wide ascii
        $fb_str_32 = "<FbData>k__BackingField" wide ascii
        $fb_str_33 = "<FbCookies>k__BackingField" wide ascii
        $fb_str_34 = "<invite_link>k__BackingField" wide ascii
        $fb_str_35 = "get_FbData" wide ascii
        $fb_str_36 = "get_invite_link" wide ascii
        $fb_str_37 = "get_Bussinesses" wide ascii
        $fb_str_38 = "GetNguong" wide ascii
        $fb_str_39 = "set_AdsAccount" wide ascii
        $fb_str_40 = "set_invite_link" wide ascii
        $fb_str_41 = "set_AllCookies" wide ascii
        $fb_str_42 = "get_business" wide ascii
        $fb_str_43 = "set_business" wide ascii
        $fb_str_44 = "<Bussinesses>k__BackingField" wide ascii
        $fb_str_45 = "GetAdsFromToken" wide ascii
        $fb_str_46 = "get_AdsAccount" wide ascii
        $fb_str_47 = "get_BmLinks" wide ascii
        $fb_str_48 = "FbDataScanner" wide ascii
        // Exfiltration-related
        $exfil_str_1 = "telegramBotClient_OnUpdate" wide ascii
        $exfil_str_2 = "telegramHandler" wide ascii
        $exfil_str_3 = "ZipArchive" wide ascii
        $exfil_str_4 = "KillItSame" wide ascii
        $exfil_str_5 = "1.txt" wide ascii
        $exfil_str_6 = ".zip" wide ascii
        $exfil_str_7 = "2.txt" wide ascii
        // Browser-related
        $browser_str_1 = "GetCookies" wide ascii
        $browser_str_2 = "get_AllCookies" wide ascii
        $browser_str_3 = "ChromiumBrowser" wide ascii
        $browser_str_4 = "myBrowsers" wide ascii
        $browser_str_5 = "get_CookiePath" wide ascii
        $browser_str_6 = "ScanFirefox" wide ascii
        $browser_str_7 = "get_FbCookies" wide ascii
        $browser_str_8 = "ScanChomium" wide ascii
        $browser_str_9 = "BrowserScanner" wide ascii
        $browser_str_10 = "ScanChronium" wide ascii
        $browser_str_11 = "CookieData" wide ascii
        $browser_str_12 = "listBrowser" wide ascii
        $browser_str_13 = "BrowserCookie" wide ascii
        $browser_str_14 = "<Cookies>k__BackingField" wide ascii
        $browser_str_15 = "AddCookie" wide ascii
        $browser_str_16 = "set_CookiePath" wide ascii
        $browser_str_17 = "Local State" wide ascii
        $browser_str_18 = "select name, path, expires_utc, is_secure, is_httponly, host_key, encrypted_value  from cookies" wide ascii
        $browser_str_19 = "Google\\Chrome\\User Data" wide ascii
        $browser_str_20 = "Microsoft\\Edge\\User Data" wide ascii
        $browser_str_21 = "Cookies" wide ascii
        $browser_str_22 = "encrypted_key\":\"" wide ascii
     condition:
        uint16(0) == 0x5A4D
        and $dotnet_core_bundle_signature
        and (
            // 7 Facebook-related with either 7 browser or 3 exfil keywords found
            (7 of ($fb_str_*) and (7 of ($browser_str_*) or 3 of ($exfil_str_*))) 
            // 7 Browser and 3 exfil keywords found
            or (7 of ($browser_str_*) and 3 of ($exfil_str_*))
        )
}