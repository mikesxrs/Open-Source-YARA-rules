//invalid hex string at $rttype1
rule PPS_With_OLEObject
{
  meta: 
    description = "PowerPoint Archives with embedded OLE indicators."
    author = "PhishMe"
  strings:
    $magic={d0 cf 11 e0} 
    $stream1="PowerPoint Document" wide
    $stream2="Current User" wide
    $rttype1={0f 00 cc 0f /*[4]*/ } 
    $rttype2={00 00 cd 0f 08 00 00 00 [4] (00|01) (00|01) /*[2]*/} 
    $rttype3={01 00 c3 0f 18 00 00 00 [4] (00|01|02) [7] 00 00 00 00  /*[4]*/} 
  condition:
    $magic at 0 and all of ($stream*)  and all of ($rttype*)
}