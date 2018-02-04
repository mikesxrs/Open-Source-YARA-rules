rule ws_f0xy_downloader {
  meta:
    description = "f0xy malware downloader"
    author = "Nick Griffin (Websense)"
    reference = "https://blogs.forcepoint.com/security-labs/new-f0xy-malware-intelligent-employs-cunning-stealth-trickery"

  strings:
    $mz="MZ"
    $string1="bitsadmin /transfer"
    $string2="del rm.bat"
    $string3="av_list="
  
  condition:
    ($mz at 0) and (all of ($string*))
}
