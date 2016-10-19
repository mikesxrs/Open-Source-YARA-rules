rule PyInstaller_Binary
{
meta:
	author = "ThreatStream Labs"
	desc = "Generic rule to identify PyInstaller Compiled Binaries”
strings:
	$string0 = "zout00-PYZ.pyz"
	$string1 = "python"
	$string2 = "Python DLL"
	$string3 = "Py_OptimizeFlag"
	$string4 = "pyi_carchive"
	$string5 = ".manifest"
	$magic = { 00 4d 45 49 0c 0b 0a 0b 0e 00 }
	
condition: 
	all of them
}