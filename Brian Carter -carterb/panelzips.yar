rule chinapic_zip

{

    meta:
        description = "Find zip archives of pony panels that have china.jpg"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "china.jpg"
        $txt2 = "config.php"
        $txt3 = "setup.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule diamondfox_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "gate.php"
        $txt2 = "install.php"
        $txt3 = "post.php"
        $txt4 = "plugins"
        $txt5 = "statistics.php"
        $magic = { 50 4b 03 04 }
        $not1 = "joomla" nocase
        
    condition:
        $magic at 0 and all of ($txt*) and not any of ($not*)
        
}

rule keybase_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "clipboard.php"
        $txt2 = "config.php"
        $txt3 = "create.php"
        $txt4 = "login.php"
        $txt5 = "screenshots.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule zeus_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "April 19, 2017"
        
    strings:
        $txt1 = "cp.php"
        $txt2 = "gate.php"
        $txt3 = "botnet_bots.php"
        $txt4 = "botnet_scripts.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule atmos_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "April 27, 2017"
        
    strings:
        $txt1 = "cp.php"
        $txt2 = "gate.php"
        $txt3 = "api.php"
        $txt4 = "file.php"
        $txt5 = "ts.php"
        $txt6 = "index.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule new_pony_panel

{

    meta:
        description = "New Pony Zips"
        
    strings:
        $txt1 = "includes/design/images/"
        $txt2 = "includes/design/style.css"
        $txt3 = "admin.php"
        $txt4 = "includes/design/images/user.png"
        $txt5 = "includes/design/images/main_bg.gif"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
