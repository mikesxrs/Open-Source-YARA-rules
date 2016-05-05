import “pe”
rule explosive_dll
{
	meta:
		author = “Check Point Software Technologies Inc.”
		info = “Explosive DLL”
 		reference = "https://www.checkpoint.com/downloads/volatile-cedar-technical-report.pdf"

	condition:
		pe.DLL and ( pe.exports(“PathProcess”) or pe.exports(“_PathProcess@4”) ) and pe.exports(“CON”)
}