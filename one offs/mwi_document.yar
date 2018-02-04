rule mwi_document : exploitdoc
{
    meta:
        description = "MWI generated document"
        reference = "https://blog.0x3a.com/post/117760824504/analysis-of-a-microsoft-word-intruder-sample"
 
    strings:
        $field_creation_tag = "{\\field{\\*\\fldinst { INCLUDEPICTURE"
        $mwistat_url = ".php?id="
        $field_closing_tag = "\\\\* MERGEFORMAT \\\\d}}{\\fldrslt}}"
 
    condition:
        all of them
}
