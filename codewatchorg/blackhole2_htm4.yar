{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "926429bf5fe1fbd531eb100fc6e53524"
	hash1 = "7b6cdc67077fc3ca75a54dea0833afe3"
	hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
	hash3 = "bd819c3714dffb5d4988d2f19d571918"
	hash4 = "9bc9f925f60bd8a7b632ae3a6147cb9e"
	hash0 = "926429bf5fe1fbd531eb100fc6e53524"
	hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
	hash7 = "386cb76d46b281778c8c54ac001d72dc"
	hash8 = "0d95c666ea5d5c28fca5381bd54304b3"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "words.dat"
	$string1 = "/icons/back.gif"
	$string2 = "data.dat"
	$string3 = "files.php"
	$string4 = "js.php"
	$string5 = "template.php"
	$string6 = "kcaptcha"
	$string7 = "/icons/blank.gif"
	$string8 = "java.dat"
condition:
	8 of them
}