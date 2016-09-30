rule blackhole2_htm3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "018ef031bc68484587eafeefa66c7082"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "/download.php"
	$string1 = "./files/fdc7aaf4a3 md5 is 3169969e91f5fe5446909bbab6e14d5d"
	$string2 = "321e774d81b2c3ae"
	$string3 = "/files/new00010/554-0002.exe md5 is 8a497cf4ffa8a173a7ac75f0de1f8d8b"
	$string4 = "./files/3fa7bdd7dc md5 is 8a497cf4ffa8a173a7ac75f0de1f8d8b"
	$string5 = "1603256636530120915 md5 is 425ebdfcf03045917d90878d264773d2"
condition:
	3 of them
}
