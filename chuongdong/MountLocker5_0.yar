rule MountLocker5_0 {
	meta:
		description = "YARA rule for MountLocker v5.0"
		reference = "http://chuongdong.com/reverse%20engineering/2021/05/23/MountLockerRansomware/"
		author = "@cPeterr"
		tlp = "white"
	strings:
		$worm_str = "========== WORM ==========" wide
		$ransom_note_str = ".ReadManual.%0.8X" wide
		$version_str = "5.0" wide
		$chacha_str = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>"
		$chacha_const = "expand 32-byte k"
		$lock_str = "[OK] locker.file > time=%0.3f size=%0.3f KB speed=%" wide
		$bat_str = "attrib -s -r -h %1"
		$IDirectorySearch_RIID = { EC A8 9B 10 F0 92 D0 11 A7 90 00 C0 4F D8 D5 A8 }
	condition:
		uint16(0) == 0x5a4d and all of them
}
