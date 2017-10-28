rule counterPHPredirectBHEK
{
	meta:
		author = "adnan.shukor@gmail.com"
		description = "Detection rule to detect compromised page injected with invisible counter.php redirector"
		ref = "http://blog.xanda.org/2013/04/05/detecting-counter-php-the-blackhole-redirector"
		cve = "NA"
		version = "1"
		impact = 4
		hide = false
	strings:
		$counterPHP = /\<iframe\ src\=\"https?\:\/\/[a-zA-Z0-9\-\.]{4,260}\/counter\.php\"\ style\=\"visibility\:\ hidden\;\ position\:\ absolute\;\ left\:\ 0px\;\ top\:\ 0px\"\ width\=\"10\"\ height\=\"10\"\/\>$/
	condition:
		all of them
}

