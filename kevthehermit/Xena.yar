rule Xena
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2015/06"
		ref = "http://malwareconfig.com/stats/Xena"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "HuntHTTPDownload"
		$b = "KuInstallation"
		$c = "PcnRawinput"
		$d = "untCMDList"
		$e = "%uWebcam"
		$f = "KACMConvertor"
		$g = "$VarUtils"
        $h = "****##"

	condition:
		all of them
}
