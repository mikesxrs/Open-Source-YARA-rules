rule iframeRedKit
{
	meta:
		author = "adnan.shukor@gmail.com"
		description = "Detection rule to detect compromised page injected with invisible iframe of Redkit redirector"
		ref = "http://blog.xanda.org/2013/02/15/redkit-redirector-injected-into-legitimate-javascript-code/"
		cve = "NA"
		version = "1.2"
		impact = 4
		hide = false
	strings:
		$iRedKit_1 = /name\=['"]?Twitter['"]?/
		$iRedKit_2 = /scrolling\=['"]?auto['"]?/
		$iRedKit_3 = /frameborder\=['"]?no['"]?/
		$iRedKit_4 = /align\=['"]?center['"]?/
		$iRedKit_5 = /height\=['"]?2['"]?/
		$iRedKit_6 = /width\=['"]?2['"]?/
		$iRedKit_7 = /src\=['"]?http:\/\/[\w\.\-]{4,}\/(([a-z]{4}\.html?(\?[hij]=\d{7})?)|([a-z]{4,}\.php\?[a-z]{4,}\=[a-f0-9]{16}))['"]?/
	condition:
		all of them
}


