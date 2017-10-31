rule PDF_EMBEDDED_DOCM

{
    meta:
        description = "Find pdf files that have an embedded docm with openaction"
        author = "Brian Carter"
        last_modified = "May 11, 2017"

    strings:
        $magic = { 25 50 44 46 2d }

        $txt1 = "EmbeddedFile"
        $txt2 = "docm)"
        $txt3 = "JavaScript" nocase

    condition:
        $magic at 0 and all of ($txt*)

}
