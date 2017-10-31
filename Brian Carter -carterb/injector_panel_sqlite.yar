rule INJECTOR_PANEL_SQLITE

{
    meta:
        description = "Find sqlite dbs used with tables inject panel"
        author = "Brian Carter"
        last_modified = "August 14, 2017"

    strings:
        $magic = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 }
        $txt1 = "CREATE TABLE Settings"
        $txt2 = "CREATE TABLE Jabber"
        $txt3 = "CREATE TABLE Users"
        $txt4 = "CREATE TABLE Log"
        $txt5 = "CREATE TABLE Fakes"
        $txt6 = "CREATE TABLE ATS_links"

    condition:
        $magic at 0 and all of ($txt*)

}
