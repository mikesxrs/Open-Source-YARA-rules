rule kbot : banker
{
     meta:
  	 author	 = "mak"
	 module	 = "kbot"
	 reference = "https://www.cert.pl/en/news/single/newest-addition-a-happy-family-kbot/"

	strings:
	   $bot_cfg = "BASECONFIG......FJ"
	   $injini  = "INJECTS.INI"
	   $kbotini = "KBOT.INI"
	   $bot0    = "BotConfig"
	   $bot1    = "BotCommunity"
	   $push_version = { 5? 68 [4] 68 [4] 5? E8 [4] 83 C4 10 85 C0 0F}
	condition: 
	   all of them
}
