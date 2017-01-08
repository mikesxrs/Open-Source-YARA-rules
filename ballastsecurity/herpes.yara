rule herpes_strings
{
	meta:
    	author = "Brian Wallace @botnet_hunter"
        authoer_email = "bwall@ballastsecurity.net"
        date = "2014-03-27"
        description = "Identify Herpes Net"
	strings:
    	$queryShort = "userandpc"
        $queryA = "userandpc=%s&admin=%s&os=%s&id=%s&hwid=%s&ownerid=%s&version=%s"
        $queryB = "userandpc=%s&admin=%s&os=%s&hwid=%s&ownerid=%s&version=%s"
   	condition:
    	2 of them

}