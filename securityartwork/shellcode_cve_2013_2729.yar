rule shellcode_cve_2013_2729
{
meta:
        author = "Manuel"
        company = "S2 Grupo"
        date = "2014-12-17"
        reference = "https://www.securityartwork.es/2014/12/18/regla-yara-para-cve-2013-2729/"
        description = "PDF con shellcode CVE 2013_2729"
        link1 = "http://www.binamuse.com/papers/XFABMPReport.pdf"
        link2 = "https://github.com/feliam/CVE-2013-2729/blob/master/XFABMPExploit.py"
        link3 = "https://github.com/feliam/CVE-2013-2729/blob/master/E10.1.4.pdf "
        link4 = "https://www.securityartwork.es/2014/09/30/pdf-deconstruido-al-
                 aroma-de-shellcode-i/"
        md5test =  "eb9228f17568704676385428d3bbefff"
strings:
        $xfa1 = "XFA 1 0 R"
        $xfa2 = "XFA 2 0 R"
        $xfa3 = "XFA 3 0 R"
        $s0 = "AcroForm 2 0 R"
        $s1 = "/Filter [/Fl"
condition:
        1 of ($xfa*) and all of ($s*)
}
