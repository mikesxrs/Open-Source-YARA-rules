
rule EQN_SMB1_PatientZero
{
meta:
  description = "Detection of network traffic towards the 1st sinkholes domain - kill switch"
  author = "Kiran Bandla - iDefense"
  reference = "https://s3.amazonaws.com/assets.accenture.com/PDF/Accenture-Security-Ransomware.pdf"
strings:
  $smb1_free_hole = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe 00 00 40 00 0c ff 00 00 00 04 11 0a 00 }
  $ipc = "\\\\%s\\IPC$"
  $userid = "__USERID__PLACEHOLDER__"
  $treeid = "__TREEID__PLACEHOLDER__"
  $old_c2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
condition:
  $smb1_free_hole and $ipc and $userid and $treeid and $old_c2
}

rule WanaCrypt0r
{
meta:
  description = "Detects artifacts from WanaCrypt0r Ransomware"
  author = "Kiran Bandla - iDefense"
  reference = "https://s3.amazonaws.com/assets.accenture.com/PDF/Accenture-Security-Ransomware.pdf"
strings:
  $a = "WanaDecryptor"
  $b = "Wana Decrypt0r"
  $c = "WanaCrypt0r"
  $d = ".wnry"
  $e = ".WNRY"
  $f = "bitcoin"
  $g = "vssadmin"
  $h = "torproject"
condition:
  4 of them
}
