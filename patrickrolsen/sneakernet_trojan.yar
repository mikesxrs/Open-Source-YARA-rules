rule sneakernet_trojan
{
meta:
	author = "@patrickrolsen"
	maltype = "Sneakernet Trojan"
	version = "0.1"
	reference = "http://www.fidelissecurity.com/webfm_send/375" 
	date = "01/30/2014"
strings:
    $s1 = "Mtx_Sp_On_PC_1_2_8"
    $s2 = "%s /c del %s"
    $s3 = "RECYCLED"
condition:
    uint16(0) == 0x5A4D and (all of ($s*))
}
