rule apt_win_bluelight_b : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        description = "North Korean origin malware which uses a custom Google App for c2 communications."
        reference = "https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/"
        date = "2021-06-21"
        hash1 = "837eaf7b736583497afb8bbdb527f70577901eff04cc69d807983b233524bfed"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $magic = "host_name: %ls, cookie_name: %s, cookie: %s, CT: %llu, ET: %llu, value: %s, path: %ls, secu: %d, http: %d, last: %llu, has: %d"
        
        $f1 = "%ls.INTEG.RAW" wide
        $f2 = "edb.chk" ascii
        $f3 = "edb.log" ascii
        $f4 = "edbres00001.jrs" ascii
        $f5 = "edbres00002.jrs" ascii
        $f6 = "edbtmp.log" ascii
        $f7 = "cheV01.dat" ascii
        
        $chrome1 = "Failed to get chrome cookie"
        $chrome2 = "mail.google.com, cookie_name: OSID"
        $chrome3 = ".google.com, cookie_name: SID,"
        $chrome4 = ".google.com, cookie_name: __Secure-3PSID,"
        $chrome5 = "Failed to get Edge cookie"
        $chrome6 = "google.com, cookie_name: SID,"
        $chrome7 = "google.com, cookie_name: __Secure-3PSID,"
        $chrome8 = "Failed to get New Edge cookie"
        $chrome9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
        $chrome10 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
        $chrome11 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
        $chrome12 = "https://mail.google.com"
        $chrome13 = "result.html"
        $chrome14 = "GM_ACTION_TOKEN"
        $chrome15 = "GM_ID_KEY="
        $chrome16 = "/mail/u/0/?ik=%s&at=%s&view=up&act=prefs"
        $chrome17 = "p_bx_ie=1"
        $chrome18 = "myaccount.google.com, cookie_name: OSID"
        $chrome19 = "Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3"
        $chrome20 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
        $chrome21 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
        $chrome22 = "https://myaccount.google.com"
        $chrome23 = "result.html"
        $chrome24 = "myaccount.google.com"
        $chrome25 = "/_/AccountSettingsUi/data/batchexecute"
        $chrome26 = "f.req=%5B%5B%5B%22BqLdsd%22%2C%22%5Btrue%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at="
        $chrome27 = "response.html"
        
        $msg1 = "https_status is %s"
        $msg2 = "Success to find GM_ACTION_TOKEN and GM_ID_KEY"
        $msg3 = "Failed to find GM_ACTION_TOKEN and GM_ID_KEY"
        $msg4 = "Failed HttpSendRequest to mail.google.com"
        $msg5 = "Success to enable imap"
        $msg6 = "Failed to enable imap"
        $msg7 = "Success to find SNlM0e"
        $msg8 = "Failed to find SNlM0e"
        $msg9 = "Failed HttpSendRequest to myaccount.google.com"
        $msg10 = "Success to enable thunder access"
        $msg11 = "Failed to enable thunder access"

        $keylogger_component1 = "[TAB]"
        $keylogger_component2 = "[RETURN]"
        $keylogger_component3 = "PAUSE"
        $keylogger_component4 = "[ESC]"
        $keylogger_component5 = "[PAGE UP]"
        $keylogger_component6 = "[PAGE DOWN]"
        $keylogger_component7 = "[END]"
        $keylogger_component8 = "[HOME]"
        $keylogger_component9 = "[ARROW LEFT]"
        $keylogger_component10 = "[ARROW UP]"
        $keylogger_component11 = "[ARROW RIGHT]"
        $keylogger_component12 = "[ARROW DOWN]"
        $keylogger_component13 = "[INS]"
        $keylogger_component14 = "[DEL]"
        $keylogger_component15 = "[WIN]"
        $keylogger_component16 = "[NUM *]"
        $keylogger_component17 = "[NUM +]"
        $keylogger_component18 = "[NUM ,]"
        $keylogger_component19 = "[NUM -]"
        $keylogger_component20 = "[NUM .]"
        $keylogger_component21 = "NUM /]"
        $keylogger_component22 = "[NUMLOCK]"
        $keylogger_component23 = "[SCROLLLOCK]"
        $keylogger_component24 = "Time: "
        $keylogger_component25 = "Window: "
        $keylogger_component26 = "CAPSLOCK+"
        $keylogger_component27 = "SHIFT+"
        $keylogger_component28 = "CTRL+"
        $keylogger_component29 = "ALT+"

    condition:
        $magic or 
        (
            all of ($f*) and 
            5 of ($keylogger_component*)
        ) or 
        24 of ($chrome*) or 
        4 of ($msg*) or 
        27 of ($keylogger_component*)
}
