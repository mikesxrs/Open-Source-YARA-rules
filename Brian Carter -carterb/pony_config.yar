rule config_php

{
    meta:
        description = "Find config.php files that have details for the db"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "$mysql_host ="
        $txt2 = "$mysql_user ="
        $txt3 = "mysql_pass ="
        $txt4 = "mysql_database ="
        $txt5 = "global_filter_list"
        $txt6 = "white-list"
        $php1 = "<?php"
        
    condition:
        $php1 at 0 and all of ($txt*)
        
}
