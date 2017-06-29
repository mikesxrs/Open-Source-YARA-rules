rule RTF_Shellcode
{
meta:
                author = "RSA-IR – Jared Greenhill"
                date = "01/21/13"
                description = "identifies RTF's with potential shellcode"
                reference = "https://community.rsa.com/community/products/netwitness/blog/2014/02/12/triaging-malicious-microsoft-office-documents-cve-2012-0158"
                filetype = "RTF"
 
strings:
                $rtfmagic={7B 5C 72 74 66}
                $scregex=/[39 30]{2,20}/
 
condition:
                ($rtfmagic at 0) and ($scregex)
}
