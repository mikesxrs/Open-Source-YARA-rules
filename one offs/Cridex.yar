
rule Malware_Cridex_Generic {
meta:
        description = "Cridex Generic"
        author = "Yara Bulk Rule Generator"
        hash = "ab0e2cbca1434ab87e8cb81f97180292"
strings:
        $s1 = /[Cc]:\\([a-zA-Z]{4,10}\\|)([a-zA-Z]{4,10}\\|)([a-zA-Z]{4,10}\\|)[a-zA-Z]{4,10}\\[a-zA-Z]{4,10}/ fullword
        $s2 = /[Cc]:\\([a-zA-Z]{4,10}\\|)([a-zA-Z]{4,10}\\|)([a-zA-Z]{4,10}\\|)[a-zA-Z]{4,10}\\[a-zA-Z]{4,10}.[a-z]{3}/ fullword
        $s3 = /[Cc]:\\[a-zA-Z]{4,10}\\[a-zA-Z]{4,10}/ fullword
condition:
        ( #s1 > 4 and #s1 < 8 ) and ( #s2 > 1 and #s2 < 5 ) and ( #s3 > 4 and #s3 < 8 ) and filesize < 200KB
}
