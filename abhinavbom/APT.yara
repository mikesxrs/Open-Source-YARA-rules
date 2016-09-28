

//PlugX APT Malware

rule PlugXXOR
{
meta:
     author = "@abhinavbom"
     maltype = "NA"
     version = "0.1"
     date = "21/09/2015"
     description = "rule for PlugX XOR Routine"
     ref1 = "7048add2873b08a9693a60135f978686"
strings:
     $hex_string = { 05 ?? ?? 00 00 8A D8 2A DC 89 45 FC 32 5D FE 81 E9 ?? ?? 00 00 2A 5D FF 89 4D F8 32 D9 2A DD 32 5D FA 2A 5D FB 32 1C 37 88 1E 46 4A 75 D2 5F 5B }
condition:
     all of them
}
 
 //APT1-Group Rule for sample used during exercise
 
rule BOUNCER_APT1 {
meta:
     author = "@abhinavbom"
     maltype = "NA"
     version = "0.1"
     date = "21/09/2015"
     info = "CommentCrew-threat-apt1"
strings:
     $s1 = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg" wide ascii
     $s2 = "IDR_DATA%d" wide ascii
     $s3 = "asdfqwe123cxz" wide ascii
     $s4 = "Mode must be 0(encrypt) or 1(decrypt)." wide ascii
condition:
     ($s1 and $s2) or ($s3 and $s4)

}
