rule sakura_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Sakura Exploit Kit Detection"
	hash0 = "d21b4e2056e5ef9f9432302f445bcbe1"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "getProperty"
	$string1 = "java/io/FileNotFoundException"
	$string2 = "LLolp;"
	$string3 = "cjhgreshhnuf "
	$string4 = "StackMapTable"
	$string5 = "onfwwa"
	$string6 = "(C)Ljava/lang/StringBuilder;"
	$string7 = "replace"
	$string8 = "LEsia$fffgss;"
	$string9 = "<clinit>"
	$string10 = "()Ljava/io/InputStream;"
	$string11 = "openConnection"
	$string12 = " gjhgreshhnijhgreshhrtSjhgreshhot.sjhgreshhihjhgreshht;)"
	$string13 = "Oi.class"
	$string14 = " rjhgreshhorjhgreshhre rajhgreshhv"
	$string15 = "java/lang/String"
	$string16 = "java/net/URL"
	$string17 = "Created-By: 1.7.0-b147 (Oracle Corporation)"
condition:
	17 of them
}
