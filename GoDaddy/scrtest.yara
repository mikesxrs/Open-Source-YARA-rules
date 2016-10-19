
rule scrtest_dropper {
    strings:
        // from 92F5B5CA948B92CA17AB1858D62215A5
        $export = "SCRTEST\x00"
        $decrypt_key = "EEB0F\x00"
        $main = { C645E44DC645E561C645E669C645E76EC645E800 }
        
    condition:
        IsPeFile and (($export and $decrypt_key) or $main)
}

rule scrtest_payload {
    strings:
        $s1 = "Consysqq.dll"
        $s2 = "Main"
        $s3 = "%c%c%c%c%c%c.exe"
        $s4 = "agmkis2\x00"

    condition:
        IsPeFile and all of them
}

