rule blackhole2_htm12
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "0d3acb5285cfe071e30be051d2aaf28a"
	hash1 = "6f27377115ba5fd59f007d2cb3f50b35"
	hash2 = "f7ffe1fd1a57d337a04d3c777cddc065"
	hash3 = "06997228f2769859ef5e4cd8a454d650"
	hash4 = "11062eea9b7f2a2675c1e60047e8735c"
	hash0 = "0d3acb5285cfe071e30be051d2aaf28a"
	hash2 = "f7ffe1fd1a57d337a04d3c777cddc065"
	hash7 = "4ec720cfafabd1c9b1034bb82d368a30"
	hash8 = "ecd7d11dc9bb6ee842e2a2dce56edc6f"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "  <title>Index of /data</title>"
	$string1 = "<tr><th colspan"
	$string2 = "</body></html>"
	$string3 = "> 20K</td><td>"
	$string4 = "/icons/layout.gif"
	$string5 = " <body>"
	$string6 = ">Name</a></th><th><a href"
	$string7 = ">spn.jar</a></td><td align"
	$string8 = ">spn2.jar</a></td><td align"
	$string9 = " <head>"
	$string10 = "-//W3C//DTD HTML 3.2 Final//EN"
	$string11 = "> 10K</td><td>"
	$string12 = ">7.9K</td><td>"
	$string13 = ">Size</a></th><th><a href"
	$string14 = "><hr></th></tr>"
condition:
	14 of them
}
