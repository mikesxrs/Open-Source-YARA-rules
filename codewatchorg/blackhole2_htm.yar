rule blackhole2_htm
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "92e21e491a90e24083449fd906515684"
	hash1 = "98b302a504a7ad0e3515ab6b96d623f9"
	hash2 = "a91d885ef4c4a0d16c88b956db9c6f43"
	hash3 = "d8336f7ae9b3a4db69317aea105f49be"
	hash4 = "eba5daf0442dff5b249274c99552177b"
	hash5 = "02d8e6daef5a4723621c25cfb766a23d"
	hash6 = "dadf69ce2124283a59107708ffa9c900"
	hash7 = "467199178ac940ca311896c7d116954f"
	hash8 = "17ab5b85f2e1f2b5da436555ea94f859"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ">links/</a></td><td align"
	$string1 = ">684K</td><td>"
	$string2 = "> 36K</td><td>"
	$string3 = "move_logs.php"
	$string4 = "files/"
	$string5 = "cron_updatetor.php"
	$string6 = ">12-Sep-2012 23:45  </td><td align"
	$string7 = ">  - </td><td>"
	$string8 = "cron_check.php"
	$string9 = "-//W3C//DTD HTML 3.2 Final//EN"
	$string10 = "bhadmin.php"
	$string11 = ">21-Sep-2012 15:25  </td><td align"
	$string12 = ">data/</a></td><td align"
	$string13 = ">3.3K</td><td>"
	$string14 = "cron_update.php"
condition:
	14 of them
}
