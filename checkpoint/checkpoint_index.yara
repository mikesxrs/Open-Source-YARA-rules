rule explosive_exe
{
  meta:
    author = "Check Point Software Technologies Inc."
    info = "Explosive EXE"
  strings:
    $MZ = "MZ"
    $DLD_S = "DLD-S:"
    $DLD_E = "DLD-E:"
  condition:
    $MZ at 0 and all of them
}

import "pe"
rule explosive_dll

{
  meta:
    author = "Check Point Software Technologies Inc."
    info = "Explosive DLL"
    reference = "https://www.checkpoint.com/downloads/volatile-cedar-technical-report.pdf"

 
  condition:
    pe.DLL
    and ( pe.exports("PathProcess") or pe.exports("_PathProcess@4") ) and 
pe.exports("CON")
}