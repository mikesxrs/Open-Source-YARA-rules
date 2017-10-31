rule chinapic_zip

{

    meta:
        description = "Find zip archives of pony panels that have china.jpg"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "china.jpg"
        $txt2 = "config.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
