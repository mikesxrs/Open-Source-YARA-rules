rule eleonore_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "94e99de80c357d01e64abf7dc5bd0ebd"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "META-INF/MANIFEST.MFManifest-Version: 1.0"
	$string1 = "wPVvVyz"
	$string2 = "JavaFX.class"
	$string3 = "{%D@'\\"
	$string4 = "JavaFXColor.class"
	$string5 = "bWxEBI}Y"
	$string6 = "$(2}UoD"
	$string7 = "j%4muR"
	$string8 = "vqKBZi"
	$string9 = "l6gs8;"
	$string10 = "JavaFXTrueColor.classeSKo"
	$string11 = "ZyYQx "
	$string12 = "META-INF/"
	$string13 = "JavaFX.classPK"
	$string14 = ";Ie8{A"
condition:
	14 of them
}
