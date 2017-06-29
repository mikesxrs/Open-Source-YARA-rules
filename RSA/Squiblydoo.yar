rule RSA_IR_Windows_COM_bypass_script
{
    meta:
        author="RSA IR"
        Date="22 Apr 2016"
        reference = "https://community.rsa.com/community/products/netwitness/blog/2016/04/26/detection-of-com-whitelist-bypassing-with-ecat"
        comment1="Detects potential scripts used by COM+ Whitelist Bypass"
        comment2="More information on bypass located at: http://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html"
 
    strings:
        $s1 = "<scriptlet>" nocase
        $s2 = "<registration" nocase
        $s3 = "classid=" nocase
        $s4 = "[CDATA[" nocase
        $s5 = "</script>" nocase
        $s6 = "</registration>" nocase
        $s7 = "</scriptlet>" nocase
 
    condition:
        all of ($s*)
}
