rule 9002_DROPPER : APT8

{
    meta:
        description = "Strings associated with 9002_DROPPER APT8"
        description = "Used for retrohunt.  Don't expect to see new samples."
        author = "Brian Carter"
        last_modified = "September 22 2015"

    strings:
        $magic = { 50 4b 03 04 (14 | 0a) 00 }

        $txt1 = "PhotoShow.class"
        $txt2 = "update.rar"
        $txt3 = "META-INF/MANIFEST.MF"
        $txt4 = "Desert.jpg"
        $txt5 = "Hydrangeas.jpg"

    condition:
       $magic at 0 and all of ($txt*)
}
