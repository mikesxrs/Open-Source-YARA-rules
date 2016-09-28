rule explosive_exe
{
  meta:
    author = "Check Point Software Technologies Inc."
    info = "Explosive EXE"
    reference = "https://www.checkpoint.com/downloads/volatile-cedar-technical-report.pdf"
    
  strings:
    $MZ = "MZ"
    $DLD_S = "DLD-S:"
    $DLD_E = "DLD-E:"
    
  condition:
    $MZ at 0 and all of them
}