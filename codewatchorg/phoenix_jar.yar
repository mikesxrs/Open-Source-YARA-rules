rule phoenix_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "a8a18219b02d30f44799415ff19c518e"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "r.JM,IM"
	$string1 = "qX$8$a"
	$string2 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProvider5"
	$string3 = "a.classPK"
	$string4 = "6;\\Q]Q"
	$string5 = "h[s] X"
	$string6 = "ToolsDemoSubClass.classPK"
	$string7 = "a.class"
	$string8 = "META-INF/MANIFEST.MFPK"
	$string9 = "ToolsDemoSubClass.classeO"
	$string10 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProviderPK"
condition:
	10 of them
}
