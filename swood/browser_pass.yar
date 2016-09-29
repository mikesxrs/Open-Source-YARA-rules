/* 
This rule attempts to find passwords in memory for hotmail, yahoo, gmail, facebook, amazon, twitter.com, linkedin.com, ebay.com and perhaps others.

Use with volatility yarascan like this: "vol.py -f mymem.img --profile=myprofile yarascan --yara-file=browserpass.yar"
 */

rule browser_pass
{
    meta:
        author = "swood"
        description = "This module is intended for forensicators and pen-testers to find passwords in memory that can help their case/engagement." 
        //Use for good not evil!" 
        reference = "https://github.com/swoodsec/YARA-RULES/blob/master/browserpass.yar"

    strings:
        $1 = "Passwd="
        $2 = "passwd="
        $3 = "Password="
        $4 = "password="
        $5 = "Pwd="
        $6 = "pwd="
        $7 = "Pass="
        $8 = "pass="
        $9 = "session_password="
        $10 = "Session_Password="

    condition:
        any of them
}
