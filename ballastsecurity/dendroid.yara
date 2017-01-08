rule dendroid
{
	meta:
    	author = "Brian Wallace @botnet_hunter"
        authoer_email = "bwall@ballastsecurity.net"
        date = "2014-08-18"
        description = "Identify Dendroid Rat"
	strings:
    	$s1 = "/upload-pictures.php?"
    	$s2 = "Opened Dialog:"
    	$s3 = "com/connect/MyService"
    	$s4 = "android/os/Binder"
    	$s5 = "android/app/Service"
   	condition:
    	all of them

}