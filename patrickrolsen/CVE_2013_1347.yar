rule html_CVE_2013_1347
{
meta:
	author = "@patrickrolsen"
	reference = "http://blogs.cisco.com/security/watering-hole-attacks-target-energy-sector"
	hashes = "00ca490898740f9b6246e300ef0ee86f and dc681f380698b2e6dca7c49f699799ad"
	date = "02/01/2014"
strings:
	$html = "html" wide ascii
	$s1 = "DOropRAM" wide ascii
	$s2 = "\\u9090\\u9090\\u9090\\u9090" wide ascii
	$s3 = "shellcode" wide ascii
	$s4 = "unicorn" wide ascii
	$s5 = "helloWorld()" wide ascii
	$s6 = "ANIMATECOLOR" wide ascii
	$s7 = "UPXIgLvY" wide ascii
condition:
	$html and 3 of ($s*)
}