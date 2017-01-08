rule locky_panel__dbaccess : malware
{
    meta:
        description = "Identify locky/ransomware panel in php"
        author = "@h3x2b <tracker _AT h3x.eu>"
        //Check also:
        //https://community.hpe.com/t5/Security-Research/Feeling-even-Locky-er/ba-p/6834311
            
    strings:
        $s01 = "userinfo"
        $s02 = "db_query_single"
        $s03 = "SELECT * FROM users WHERE id=?"
        $s04 = "SESSION['uid']"
        $s05 = "goto not_logged_in"
        $s06 = "SELECT id,pass,enabled FROM users WHERE name=?"
        $s07 = "count(id) as Total"
        $s08 = "count(NULLIF(completed,0)) as Completed"
        $s09 = "count(NULLIF(btc_payed,0)) as Paid"
        $s10 = "sum(btc_payed)"
        $s11 = "Amount BTC"
        $s12 = "SELECT affid as User"
        $s13 = "columns FROM clients GROUP BY affid"
        $s14 = "format_btc(strval("
        
    condition:
        all of them

}



rule locky_panel__botgeneration : malware
{
    meta:
        description = "Identify locky/ransomware builder"
        author = "@h3x2b <tracker _AT h3x.eu>"
        //Check also:
        //https://community.hpe.com/t5/Security-Research/Feeling-even-Locky-er/ba-p/6834311

    strings:
        $s01 = "make_bot_exe"
        $s02 = "BOT_EXES_PATH"
        $s03 = "Locky_{*}.exe"
        $s04 = "Location:"
        $s05 = "BOT_EXES_URL"

    condition:
        all of them

}


rule locky_panel__bitcoins : malware
{
    meta:
        description = "Identify locky/ransomware panel on the bitcoins handling"
        author = "@h3x2b <tracker _AT h3x.eu>"
        //Check also:
        //https://community.hpe.com/t5/Security-Research/Feeling-even-Locky-er/ba-p/6834311

    strings:
        $s01 = "registered"
        $s02 = "visited"
        $s03 = "ip"
        $s04 = "affid"
        $s05 = "completed"
        $s06 = "lang"
        $s07 = "is_server"
        $s08 = "corporate"
        $s09 = "os_ver"
        $s10 = "is_x64"
        $s11 = "btc_address"
        $s12 = "btc_needed"
        $s13 = "btc_payed"
        $s14 = "txfree"
        $s15 = "txid"

    condition:
        all of them

}



