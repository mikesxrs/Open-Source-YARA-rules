rule UNC5221_WIREFIRE_Webshell
{
meta:
   author = "QuoIntelligence"
   description = "Detects the web shell WIREFIRE tracked by Mandiant and similar variants using common pack / unpack methods"
    date = "2024-01-19"
    report = "https://quointelligence.eu/2024/01/unc5221-unreported-and-undetected-wirefire-web-shell-variant/"
strings:
   $s1 = "zlib.decompress(aes.decrypt(base64.b64decode(" ascii
   $s2 = "from Cryptodome.Cipher import AES" ascii
   $p1 = "aes.encrypt(t+('\\x00'*(16-len(t)%16))" ascii
condition:
   filesize < 10KB and all of ($s*) or any of ($p*)
}
