import "pe"

rule Bannerjack
{
 	meta:
 		author = "Symantec Security Response"
 		date = "2015-07-01"
 		description = "Butterfly BannerJack hacktool"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"
 	strings:
 		$str_1 = "Usage: ./banner-jack [options]"
 		$str_2 = "-f: file.csv"
 		$str_3 = "-s: ip start"
 		$str_4 = "-R: timeout read (optional, default %d secs)"
 	condition:
 		all of them
}