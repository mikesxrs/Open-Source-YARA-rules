rule stdbot_std : malware linux
{
	meta:
		author = "@h3x2b <tracker@h3x.eu>"
		description = "Detects STDbot samples - 20161009"
		//Check also:
		//http://tracker.h3x.eu/corpus/760
		//http://tracker.h3x.eu/info/760
		//http://blog.malwaremustdie.org/2016/02/mmd-0052-2016-skidddos-elf-distribution.html
		//http://blog.malwaremustdie.org/2016/04/mmd-0053-2016-bit-about-elfstd-irc-bot.html

	strings:
		$irc_00 = "CONNECT"
		$irc_01 = "NICK"
		$irc_02 = "PING"
		$irc_03 = "JOIN"

		$std_00 = ":>bot +std"
		$std_01 = "PRIVMSG"
		$std_02 = "[STD]Hitting"


	condition:
		//ELF magic
		uint32(0) == 0x464c457f and

		//Contains all of the IRC strings
		all of ($irc_*) and

		//Contains all of the strings
		all of ($std_*)
}


rule stdbot_std2 : malware linux
{
	meta:
		author = "@h3x2b <tracker@h3x.eu>"
		description = "Detects STDbot samples - 20161009"
		//Check also:
		//http://tracker.h3x.eu/corpus/760
		//http://tracker.h3x.eu/info/760
		//http://blog.malwaremustdie.org/2016/04/mmd-0053-2016-bit-about-elfstd-irc-bot.html
		//Samples:
		//fa856be9e8018c3a7d4d2351398192d8  pty
		//80ffb3ad788b73397ce84b1aadf99b  tty0
		//d47a5da273175a5971638995146e8056  tty1
		//2c1b9924092130f5c241afcedfb1b198  tty2
		//f6fc2dc7e6fa584186a3ed8bc96932ca  tty3
		//b629686b475eeec7c47daa72ec5dffc0  tty4
		//c97f99cdafcef0ac7b484e79ca7ed503  tty5

	strings:
		$std_00 = "shitteru koto dake"
		$std_01 = "nandemo wa shiranai wa yo"


        condition:
		//ELF magic
		uint32(0) == 0x464c457f and

		//Contains all of the strings
		all of ($std_*)
}

