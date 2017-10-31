rule tables_inject

{

    meta:
        description = "Find zip archives of tables inject panel"
        author = "Brian Carter"
        last_modified = "August 14, 2017"
        
    strings:
        $txt1 = "tinymce"
        $txt2 = "cunion.js"
        $txt3 = "tables.php"
        $txt4 = "sounds/1.mp3"
        $txt5 = "storage/db.sqlite"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
