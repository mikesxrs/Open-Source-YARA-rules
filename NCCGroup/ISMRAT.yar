rule trojan_ismrat_gen {
 meta:
 description = "ISM RAT"
 author = "Ahmed Zaki"
 md5 = "146a112cb01cd4b8e06d36304f6bdf7b , fa3dbe37108b752c38bf5870b5862ce5,
bf4b07c7b4a4504c4192bd68476d63b5"
 reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/february/ism-rat/"
strings:
$s1 = "WinHTTP Example/1.0" wide
$s2 = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0" wide
$s3 = "|||Command executed successfully"
$dir = /Microsoft\\Windows\\Tmpe[a-z0-9]{2,8}/
condition:
uint16(0) == 0x5A4D and all of them
}
