/*
	yara-rule-havex-netscan.yar
		This searches for "~tracedscn.yls" or 
		port activity indicative of the 
		W32.Havex.Netscan malware module.
		NOTE: 5 ports are scanned by W32.Havex.Netscan; only 44818 was 
		chosen due to its high port number and hex rule limiting the 
		chance for a false positive! 
	Val A. Red, 20151206
*/

rule W32HavexNetscan
{
	meta:
		description = "Havex.Netscan search based on temp file & ports"
		in_the_wild = true
		reference = "https://github.com/vred/yara-rule-havex-netscan/blob/master/havex-netscan.yar"
	strings:
		$file = "~tracedscn.yls" wide nocase 
		//$p1 = { 0A F1 2? } 	// Rslinx 44818 only selected 
	condition:
		($file)// and ($p1)
}