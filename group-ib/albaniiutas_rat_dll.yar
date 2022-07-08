rule albaniiutas_rat_dll
{
  meta:
    author = "Dmitry Kupin"
    company = "Group-IB"
    family = "albaniiutas.rat"
    description = "Suspected Albaniiutas RAT (fileless)"
    reference = "https://blog.group-ib.com/task"
    sample = "fd43fa2e70bcc3b602363667560494229287bf4716638477889ae3f816efc705" // dumped
    severity = 9
    date = "2021-07-06"

  strings:
    $rc4_key = { 00 4C 21 51 40 57 23 45 24 52 25 54 5E 59 26 55 2A 41 7C 7D 74 7E 6B 00 } // L!Q@W#E$R%T^Y&U*A|}t~k
    $aes256_str_seed = { 00 30 33 30 34 32 37 36 63 66 34 66 33 31 33 34 35 00 } // 0304276cf4f31345
    $s0 = "http://%s/%s/%s/" fullword ascii
    $s1 = "%s%04d/%s" fullword ascii
    $s2 = "GetRemoteFileData error!" fullword ascii
    $s3 = "ReadInjectFile error!" fullword ascii
    $s4 = "%02d%02d" fullword ascii
    $s5 = "ReadInject succeed!" fullword ascii
    $s6 = "/index.htm" fullword ascii
    $s7 = "commandstr" fullword ascii
    $s8 = "ClientX.dll" fullword ascii
    $s9 = "GetPluginObject" fullword ascii
    $s10 = "D4444 0k!" fullword ascii
    $s11 = "D5555 E00r!" fullword ascii
    $s12 = "U4444 0k!" fullword ascii
    $s13 = "U5555 E00r!" fullword ascii

  condition:
    5 of them
}
