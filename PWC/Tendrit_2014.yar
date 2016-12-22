rule Tendrit_2014 : OnePHP

{

meta:

       author = "PwC Cyber Threat Operations   :: @tlansec"

       date="2014-12"

       ref="[http://pwc.blogs.com/cyber_security_updates/2014/12/festive-spearphishing-merry-christmas-from-an-apt-actor.html]"

       hash = "7b83a7cc1afae7d8b09483e36bc8dfbb"

strings:

       $url1="favicon"

       $url2="policyref"

       $url3="css.ashx"

       $url4="gsh.js"

       $url5="direct"



       $error1="Open HOST_URL error"

       $error2="UEDone"

       $error3="InternetOpen error"

       $error4="Create process fail"

       $error5="cmdshell closed"

       $error6="invalid command"

       $error7="mget over&bingle"

       $error8="mget over&fail"

 condition:

       (all of ($url*) or all of ($error*)) and filesize < 300KB

}
