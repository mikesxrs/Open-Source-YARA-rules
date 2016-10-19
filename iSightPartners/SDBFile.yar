rule SDBFile
{
	meta:
		author = "iSight Partners"
		author2 = "Sean Pierce"
		description = "Shim Database files"
		reference = "https://www.blackhat.com/docs/asia-14/materials/Erickson/Asia-14-Erickson-Persist-It-Using-And-Abusing-Microsofts-Fix-It-Patches.pdf"
		reference2 = "https://www.blackhat.com/docs/eu-15/materials/eu-15-Pierce-Defending-Against-Malicious-Application-Compatibility-Shims.pdf"
 	strings:
 		$magic = { 73 64 62 66 } // sdbf
 	condition:
 		$magic at 8 and
		md5 != "B02B4B8924F019BDE57484A55DC5CA57" and
		md5 != "BA17F2DA98A8A375D22CB33C8E83A146" and
		md5 != "EC9D5F0AE38EC4A97E70960264B7D07D" and
		md5 != "4C7B2F691885878EDBAE48760A7E3FB9" and
		md5 != "1D8C1280D38C526C7041E72DB8D70DC1" and
		md5 != "8006552125C9D590843192543668BB0B"
}

