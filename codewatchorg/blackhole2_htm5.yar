rule blackhole2_htm5
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
	hash1 = "a09bcf1a1bdabe4e6e7e52e7f8898012"
	hash2 = "40db66bf212dd953a169752ba9349c6a"
	hash3 = "25a87e6da4baa57a9d6a2cdcb2d43249"
	hash4 = "6f4c64a1293c03c9f881a4ef4e1491b3"
	hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
	hash2 = "40db66bf212dd953a169752ba9349c6a"
	hash7 = "4bdfff8de0bb5ea2d623333a4a82c7f9"
	hash8 = "b43b6a1897c2956c2a0c9407b74c4232"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "ruleEdit.php"
	$string1 = "domains.php"
	$string2 = "menu.php"
	$string3 = "browsers_stat.php"
	$string4 = "Index of /library/templates"
	$string5 = "/icons/unknown.gif"
	$string6 = "browsers_bstat.php"
	$string7 = "oses_stat.php"
	$string8 = "exploits_bstat.php"
	$string9 = "block_config.php"
	$string10 = "threads_bstat.php"
	$string11 = "browsers_bstat.php"
	$string12 = "settings.php"
condition:
	12 of them
}
