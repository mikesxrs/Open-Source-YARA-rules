rule RansomCryptoApp_A
{
	meta:
		Description  = "Ransom.CryptoApp.sm"
		ThreatLevel  = "5"

	strings:

		$pdb0 = "CryptoApp.pdb" ascii wide
		$pdb1 = "KeepAlive.pdb" ascii wide
		$pdb2 = "SelfDestroy.pdb" ascii wide
		$pdb3 = "CoreDownloader.pdb" ascii wide

	condition:
		(3 of them) or (any of ($pdb*))
}

rule RansomCryptoWallApp_3
{
	meta:
		Description  = "Ransom.CryptoWall.sm"
		ThreatLevel  = "5"

	strings:

		$s0 = "spatopayforwin.com" ascii wide
		$s1 = "bythepaywayall.com" ascii wide
		$s2 = "lowallmoneypool.com" ascii wide
		$s3 = "transoptionpay.com" ascii wide
		$s4 = "HELP_DECRYPT" ascii wide nocase

		$s5 = "speralreaopio.com" ascii wide
        $s6 = "vremlreafpa.com" ascii wide
        $s7 = "wolfwallsreaetpay.com" ascii wide
        $s8 = "askhoreasption.com" ascii wide

	condition:
		any of ($s*)
}

rule RansomCBTLockerApp
{
	meta:
		Description  = "Ransom.CBTLocker.sm"
		ThreatLevel  = "5"

	strings:

		$s0 = "Your personal files are encrypted by CTB-Locker" ascii wide
		$s1 = "Your documents, photos, databases and other important files have been encrypted with strongest encryption and unique key,generated for this computer" ascii wide
		$s2 = "Private decryption key is stored on a secret Internet server and nobody can decrypt your files until you pay and obtain the private key." ascii wide
		$s3 = "If you see the main locker window, follow the instructions on the locker. Overwise, it's seems that you or your antivirus deleted the locker program" ascii wide

		$s6 = "keme132.DLL" ascii wide
		$s7 = "klospad.pdb" ascii wide

	condition:
		(any of ($s*)) or (3 of them)
}

rule RansomEncryptorRaaSApp
{
	meta:
		Description  = "Ransom.EncryptorRaaS.sm"
		ThreatLevel  = "5"

	strings:

		$s0 = "decryptoraveidf7.onion.to" ascii wide
		$s1 = "encryptor_raas_readme_liesmich.txt" ascii wide
		$s2 = "The files on your computer have been securely encrypted by Encryptor RaaS" ascii wide
		$s3 = "Die Dateien auf Ihrem Computer wurden von Encryptor RaaS sicher verschluesselt" ascii wide
		$s4 = "encryptor3awk6px.onion" ascii wide

	condition:
		any of ($s*)
}

rule RansomSampleTeslaCryptA
{
	meta:
		Description  = "Ransom.TeslaCrypt.sm"
		ThreatLevel  = "5"

	strings:
		$ = "HOWTO_RESTORE_FILES.TXT" ascii wide nocase
		$ = "HOWTO_RESTORE_FILES.bmp" ascii wide nocase
		$ = "HOWTO_RESTORE_FILES.HTML" ascii wide nocase
	condition:
		any of them
}

rule RansomSampleTeslaCryptB
{
	meta:
		Description  = "Ransom.TeslaCrypt.B.sm"
		ThreatLevel  = "5"

	strings:
		$ = "help_recover_instructions" ascii wide nocase
		$ = "help_recover_instructions.TXT" ascii wide nocase
		$ = "help_recover_instructions.png" ascii wide nocase
	condition:
		any of them
}

rule RansomSampleChimeraB
{
	meta:
		Description  = "Ransom.Win32.Chimera.sm"
		ThreatLevel  = "5"

	strings:
		$ = "YOUR_FILES_ARE_ENCRYPTED.HTML" ascii wide nocase
		$ = "Projects\\Ransom\\bin\\Release\\Core.pdb" ascii wide nocase
		$ = "BM-2cW44Yq9DWbHYnRSfzBLVxvE6WjadchNBt" ascii wide nocase
	condition:
		any of them
}

rule RansomSampleLeChiffre
{
	meta:
		Description  = "Ransom.Win32.LeChiffre.sm"
		ThreatLevel  = "5"

	strings:
		$ = "LeChiffre" ascii wide nocase
		$ = "decrypt.my.files@gmail.com" ascii wide nocase
		$ = "http://184.107.251.146/sipvoice.php?" ascii wide nocase
		$ = "_secret_code.txt" ascii wide nocase
		$ = "_How to decrypt LeChiffre files.html" ascii wide nocase
	condition:
		2 of them
}

rule RansomSampleHydraCrypt
{
	meta:
		Description  = "Ransom.Win32.HydraCrypt.sm"
		ThreatLevel  = "5"

	strings:
		$ = "README_DECRYPT_HYDRA_ID_" ascii wide nocase
		$ = "hydracrypt_ID_" ascii wide nocase
		$ = "HYDRACRYPT" ascii wide nocase
		$ = "ccc=hydra01_" ascii wide nocase
	condition:
		2 of them
}

rule RansomFilecoderA
{
	meta:
		Description  = "Ransom.FileCoder.A.vb"
		ThreatLevel  = "5"

	strings:
		$ = "Guji36" ascii wide
		$ = "Burnamedoxi" ascii wide
		$ = "S48H1G54JSPSODKMGdfH1FD5G8DSDPSDKMFSSJJPGMCNDHS2FH5" ascii wide
	condition:
		any of them
}

rule RansomSampleLockyCrypt
{
	meta:
		Description  = "Ransom.Win32.Locky.sm"
		ThreatLevel  = "5"

	strings:
		$s1 = ".locky" ascii wide nocase
		$ = "&encrypted=" ascii wide nocase
		$s2 = "_Locky_recover_instructions.txt" ascii wide nocase
		$s3 = "_Locky_recover_instructions.bmp" ascii wide nocase
		$ = "94.242.57.45" ascii wide nocase
		$ = "46.4.239.76" ascii wide nocase
		$s6 = "Software\\Locky" ascii wide nocase
		$ = "vssadmin.exe Delete Shadows" ascii wide nocase
		$ = "Locky" ascii wide nocase

		$o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } // address=0x4144a7
		$o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } // address=0x413863

	condition:
		(3 of them) or (any of ($s*)) or (all of ($o*))
}

rule RansomLocky
{
	meta:
		Description  = "Ransom.Locky.ab"
		ThreatLevel  = "5"
	strings:
		$mz = { 4d 5a }

		$inst1 = "_HELP_instructions.bmp" ascii wide
		$inst2 = "_HELP_instructions.html" ascii wide
		$inst3 = "_HELP_instructions.txt" ascii wide
		$inst4 = "_Locky_recover_instructions.bmp" ascii wide
		$inst5 = "_Locky_recover_instructions.txt" ascii wide
		$deleteShadows = "vssadmin.exe" ascii wide // universal Ransom detect :)

		$cyrptEP1 = {e8 95 23 ff ff 86 c8 86 ea e9 8d 23 ff ff 86 f4 e9 84 23 ff ff 86 c5} // EP paked locy
		$cyrptEP2 = {55 8b ec eb 68 eb 66 eb 64 6a 00 6a 00 6a 00 6a 00 6a 00} // EP packed locy 2
	
	condition:
		( $mz at 0 ) and 
		(
			$cyrptEP1 at entrypoint or
			$cyrptEP2 at entrypoint or 
			(any of ($inst*)) or 
			$deleteShadows
		)
}

rule RansomImportDetect
{
	meta:
		Description  = "Ransom.Gen.ab"
		ThreatLevel  = "3"
	condition:
		(pe.imports("Kernel32.dll", "FindFirstFileW") or pe.imports("Kernel32.dll", "FindFirstFileA")) and
		(pe.imports("Kernel32.dll", "FindNextFileW") or pe.imports("Kernel32.dll", "FindNextFileA")) and
		(pe.imports("Advapi32.dll", "CryptAcquireContextW") or pe.imports("Advapi32.dll", "CryptAcquireContextA")) and
		pe.imports("Advapi32.dll", "CryptEncrypt") and
		pe.imports("Advapi32.dll", "CryptGenRandom")
}

