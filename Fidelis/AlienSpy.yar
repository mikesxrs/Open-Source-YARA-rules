rule AlienSpy {
meta:
	description = "AlienSpy"
	author = "Fidelis Cybersecurity"
	reference = "Fidelis Threat Advisory #1015 - Ratting on AlienSpy - Apr 08, 2015"

strings:
	$sa_1 = "META-INF/MANIFEST.MF" 
	$sa_2 = "Main.classPK"
	$sa_3 = "plugins/Server.classPK"
	$sa_4 = "IDPK"

	$sb_1 = "config.iniPK"
	$sb_2 = "password.iniPK"
	$sb_3 = "plugins/Server.classPK"
	$sb_4 = "LoadStub.classPK"
	$sb_5 = "LoadStubDecrypted.classPK"
	$sb_7 = "LoadPassword.classPK"
	$sb_8 = "DecryptStub.classPK"
	$sb_9 = "ClassLoaders.classPK"

	$sc_1 = "config.xml"
	$sc_2 = "options"
	$sc_3 = "plugins"
	$sc_4 = "util"
	$sc_5 = "util/OSHelper"
	$sc_6 = "Start.class"
	$sc_7 = "AlienSpy"
	$sc_8 = "PK"

condition:
	(all of ($sa_*)) or (all of ($sb_*)) or (all of ($sc_*))

}