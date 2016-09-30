rule WormWin32PhorpiexSampleM
{
	meta:
		Description  = "Worm.Phorpiex.sm"
		ThreatLevel  = "5"

	strings:
		$ = "paltalk.exe" ascii wide
		$ = "Xfire.exe" ascii wide
		$ = "googletalk.exe" ascii wide
		$ = "Skype.exe" ascii wide
		$ = "http://goo.gl" ascii wide
		
		$ = "qemu" ascii wide
		$ = "virtual" ascii wide
		$ = "vmware" ascii wide
		$ = "%s\\winsvcon.txt" ascii wide
		$ = "%s\\rmrf%i%i%i%i.bat" ascii wide
		$ = "%s%s.txt" ascii wide
		$ = "%s%s.zip" ascii wide
		$ = "IMG%s-JPG.scr" ascii wide
		$ = "Microsoft Windows Manager" ascii wide
		$ = "winbtc.exe" ascii wide
		$ = "winmgr.exe" ascii wide
		$ = "winraz.exe" ascii wide
		$ = "winsam.exe" ascii wide
		$ = "winsvc.exe" ascii wide
		$ = "winsvn.exe" ascii wide
		$ = ".exe" ascii wide
		$ = ".bat" ascii wide
		$ = ".vbs" ascii wide
		$ = ".pif" ascii wide
		$ = ".cmd" ascii wide
		$ = "%s\\autorun.inf" ascii wide
		
		$ = "ti piace la foto?" ascii wide
		$ = "hai visto questa foto?" ascii wide
		$ = "la foto e grandiosa!" ascii wide
		$ = "ti ricordi la Foto?" ascii wide
		$ = "conosci la persona in questa foto?" ascii wide
		$ = "chi e in questa foto?" ascii wide
		$ = "nu imi mai voi face niciodat poze!! toate ies urate ca asta." ascii wide
		$ = "spune-mi ce crezi despre poza asta." ascii wide
		$ = "asta e ce-a mai funny poza! tu ce zici?" ascii wide
		$ = "zimi ce crezi despre poza asta?" ascii wide
		$ = "pogled na ovu sliku" ascii wide
		$ = "bu resmi bakmak" ascii wide
		$ = "pozri sa na tento obr" ascii wide
		$ = "pogled na to sliko" ascii wide
		$ = "vaata seda pilti" ascii wide
		$ = "spojrzec na to zdjecie" ascii wide
		$ = "Ieskatieties " ascii wide
		$ = "kyk na hierdie foto" ascii wide
		$ = "tell me what you think of this picture i edited" ascii wide
		$ = "this is the funniest photo ever!" ascii wide
		$ = "tell me what you think of this photo" ascii wide
		$ = "i don't think i will ever sleep again after seeing this photo" ascii wide
		$ = "i cant believe i still have this picture" ascii wide
		$ = "should i make this my default picture?" ascii wide
		$ = "ken je dat foto nog?" ascii wide
		$ = "kijk wat voor een foto ik heb gevonden" ascii wide
		$ = "ik hoop dat jij het net bent op dit foto" ascii wide
		$ = "ben jij dat op dit foto?" ascii wide
		$ = "dit foto zal je echt eens bekijken!" ascii wide
		$ = "ken je dit foto al?" ascii wide
		$ = "olhar para esta foto" ascii wide
		$ = "devrais-je mettre cette photo de profile?" ascii wide
		$ = "c'est la photo la plus marrante!" ascii wide
		$ = "dis moi ce que tu pense de cette photo de moi?" ascii wide
		$ = "mes parents vont me tu" ascii wide
		$ = "creo que no voy a poder dormir m" ascii wide
		$ = "esta foto es gracios" ascii wide
		$ = "mis padres me van a matar si ven esta foto mia, que decis?" ascii wide
		$ = "mira como saliste en esta foto jajaja" ascii wide
		$ = "wie findest du das foto?" ascii wide
		$ = "hab ich dir das foto schon gezeigt?" ascii wide
		$ = "schau mal welches foto ich gefunden hab" ascii wide
		$ = "bist du das auf dem foto?" ascii wide
		$ = "kennst du das foto schon?" ascii wide
		$ = "I cant believe I still have this picture" ascii wide 
		$ = "I love your picture!" ascii wide 
		$ = "Is this you??" ascii wide 
		$ = "Picture of you???" ascii wide 
		$ = "Should I upload this picture on facebook?" ascii wide
		$ = "Someone showed me your picture" ascii wide 
		$ = "Someone told me it's your picture" ascii wide 
		$ = "Take a look at my new picture please" ascii wide 
		$ = "Tell me what you think of this picture" ascii wide 
		$ = "This is the funniest picture ever!" ascii wide 
		$ = "What do you think of my new hair" ascii wide 
		$ = "What you think of my new hair color?" ascii wide 
		$ = "What you think of this picture?" ascii wide 
		$ = "You look so beautiful on this picture" ascii wide 
		$ = "You should take a look at this picture" ascii wide 
		$ = "Your photo isn't really that great" ascii wide

	condition:
		5 of them
}