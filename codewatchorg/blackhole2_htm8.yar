rule blackhole2_htm8
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "3f47452c1e40f68160beff4bb2a3e5f4"
	hash1 = "1e2ba0176787088e3580dfce0245bc16"
	hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
	hash3 = "f5e16a6cd2c2ac71289aaf1c087224ee"
	hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
	hash0 = "3f47452c1e40f68160beff4bb2a3e5f4"
	hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
	hash7 = "6702efdee17e0cd6c29349978961d9fa"
	hash8 = "287dca9469c8f7f0cb6e5bdd9e2055cd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ">Description</a></th></tr><tr><th colspan"
	$string1 = ">Name</a></th><th><a href"
	$string2 = "main.js"
	$string3 = "datepicker.js"
	$string4 = "form.js"
	$string5 = "<address>Apache/2.2.15 (CentOS) Server at online-moo-viii.net Port 80</address>"
	$string6 = "wysiwyg.js"
condition:
	6 of them
}
