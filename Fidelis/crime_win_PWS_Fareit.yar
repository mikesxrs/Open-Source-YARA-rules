rule crime_win_PWS_Fareit
{
meta:
	description = "Fareit password stealer"
	author = "General Dynamics Fidelis Cybersecurity Solutions - Threat Research Team"
	reference = "https://www.fidelissecurity.com/sites/default/files/FTA_1016_Pushdo.pdf"
	date = "20150414"
	filetype = "exe"
	hash_1 = "e93799591429756b7a5ad6e44197c020"
	hash_2 = "891823de9b05e17def459e04fb574f94"
	hash_3 = "6e54267c787fc017a2b2cc5dc5273a0a"
	hash_4 = "40165ee6b1d69c58d3c0d2f4701230fa"
	hash_5 = "de3b206a8066db48e9d7b0a42d50c5cd"
	hash_6 = "b988944f831c478f5a6d71f9e06fbc22"
	hash_7 = "7b7584d86efa2df42fe504213a3d1d2c"
	hash_8 = "f088b291af1a3710f99c33fa37f68602"
strings:
	$mz = {4d5a}
 	$s1 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins"
	$s2 = "gate.php"
	$s3 = "STATUS-IMPORT-OK"
	$s4 = "Client Hash"
	$s5 = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"
	$c1 = "wiseftpsrvs.bin"
	$c2 = "out.bin"
condition:
	$mz at 0 and filesize < 105KB and all of ($s*) and ($c1 or $c2)
}