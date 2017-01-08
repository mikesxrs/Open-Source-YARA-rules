private rule IsPE
{
  condition:
     // MZ signature at offset 0 and ...
     uint16(0) == 0x5A4D and
     // ... PE signature at offset stored in MZ header at 0x3C
     uint32(uint32(0x3C)) == 0x00004550
}




rule fastposloader: posmalware{

meta:
	author = "Nikolaos Pantazopoulos"
	date = "20/11/2016"
	description = "FastPos malware"

strings:

	$string1 = "keylogaaa9logbbb7"
	$string2 = "\\_hookRecvSrvc\\Release\\_hookRecvSrvc.pdb"
	$string3 = "\\_hookProc\\Release\\_hookProc.pdb"
	$string4 = "statuslog&log=procinstalled"
	$string5 = "\\_hookKlg\\Release\\_hookKlg.pdb"
	$string6 = "CLAXCSSPLS"
	$string7 = "statuslog&log=kbinjected"
	$string8 = "\\_hookLoader\\Release\\_hookLoader.pdb"
 	$string9 = "\\\\.\\mailslot\\trackslot"
condition:
	all of($string*) and IsPE
}
