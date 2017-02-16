rule unidentified_malware_two
{
meta:
  Author = "US-CERT Code Analysis Team"
  Date = "16JAN17"
  Incident = "10105049"
  File = "9f918fb741e951a10e68ce6874b839aef5a26d60486db31e509f8dcaa13acec5"
  MD5 = "617BA99BE8A7D0771628344D209E9D8A"
  reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"


strings:
  $my_string_one = "/zapoy/gate.php"
  $my_string_two = { E3 40 FE 45 FD 0F B6 45 FD 0F B6 14 38 88 55 FF 00 55 FC 0F B6 45 FC 8A 14 38 88 55 FE 0F B6 45 FD 88 14 38
0F B6 45 FC 8A 55 FF 88 14 38 8A 55 FF 02 55 FE 8A 14 3A 8B 45 F8 30 14 30 }
  $my_string_three = "S:\\Lidstone\\renewing\\HA\\disable\\In.pdb"
  $my_string_four = { 8B CF 0F AF CE 8B C6 99 2B C2 8B 55 08 D1 F8 03 C8 8B 45 FC 03 C2 89 45 10 8A 00 2B CB 32 C1 85 DB 74 07 }
  $my_string_five = "fuckyou1"
  $my_string_six = "xtool.exe"

condition:
  ($my_string_one and $my_string_two) or ($my_string_three or $my_string_four) or ($my_string_five and $my_string_six)
}
