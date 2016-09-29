//Author @jsmesa

import "cuckoo"

rule koler_domains
{
	meta:
		description = "Old Koler.A domains examples"
		sample = "2e1ca3a9f46748e0e4aebdea1afe84f1015e3e7ce667a91e4cfabd0db8557cbf"

	condition:
		cuckoo.network.dns_lookup(/police-scan-mobile.com/) or
		cuckoo.network.dns_lookup(/police-secure-mobile.com/) or
		cuckoo.network.dns_lookup(/mobile-policeblock.com/) or
		cuckoo.network.dns_lookup(/police-strong-mobile.com/) or
		cuckoo.network.dns_lookup(/video-porno-gratuit.eu/) or
		cuckoo.network.dns_lookup(/video-sartex.us/) or 
		cuckoo.network.dns_lookup(/policemobile.biz/)
}

rule koler_builds
{
	meta:
		description = "Koler.A builds"

	strings:
		$0 = "buildid"
		$a = "DCEF055EEE3F76CABB27B3BD7233F6E3"
		$b = "C143D55D996634D1B761709372042474"
		
	condition:
		$0 and ($a or $b)
		
}

rule koler_class
{
	meta:
		description = "Koler.A class"

	strings:
		$0 = "FIND_VALID_DOMAIN"
		$a = "6589y459"
		
	condition:
		$0 and $a
		
}

rule koler_D
{
	meta:
		description = "Koler.D class"

	strings:
		$0 = "ZActivity"
		$a = "Lcom/android/zics/ZRuntimeInterface"
		
	condition:
		($0 and $a)
		
}

rule dropper:realshell {
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$a = "hexKey:"
		$b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
	
	condition:
		any of them
}

/*
//https://koodous.com/#/apks/c77eed5e646b248079507973b2afcf866234001166f6d280870e624932368529
//https://koodous.com/#/apks/bdfbf9de49e71331ffdfd04839b2b0810802f8c8bb9be93b5a7e370958762836
//https://koodous.com/#/apks/fcf88c8268a7ac97bf10c323eb2828e2025feea13cdc6554770e7591cded462d

import "androguard"


rule mobidash : advertising
{
	meta:
		description = "This rule detects MobiDash advertising"
		sample = "c77eed5e646b248079507973b2afcf866234001166f6d280870e624932368529"

	strings:
		$a = "res/raw/ads_settings.json"
		$b = "IDATx"

	condition:
		($a or $b) and androguard.activity(/mobi.dash.*//*)

		
}

*/