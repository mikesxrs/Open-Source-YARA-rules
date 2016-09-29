rule Yarochkin
{
	meta:
		author = "XecScan API 2.0 beta"
		date = "2013-0706 02:26:40"
		description ="scan.xecure-lab.com"
		hash0 = "68d3bf4e11a65a6ba8170c3b77cc49cb"
		Reference = "https://media.blackhat.com/us-13/US-13-Yarochkin-In-Depth-Analysis-of-Escalated-APT-Attacks-Slides.pdf"

	strings:
		$string0 = "blog.yam.com"
		$string1 = "http://blog.yam.com/minzhu0906/article/54726977"
		$string2 = "BLOG.YAM.COM"
		
	condition:
		any of them

}