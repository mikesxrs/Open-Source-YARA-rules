rule RockLoader{
  meta:
    name = "RockLoader"
    description = "RockLoader Malware"
    author = "@seanmw"
        
  strings:
    $hdr = {4d 5a 90 00}
    $op1 = {39 45 f0 0f 8e b0 00 00 00}
    $op2 = {32 03 77 73 70 72 69 6e 74 66 41 00 ce 02 53 65}
        
  condition:
    $hdr at 0 and all of ($op*) and filesize < 500KB
}