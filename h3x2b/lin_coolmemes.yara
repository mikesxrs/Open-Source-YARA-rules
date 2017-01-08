rule coolmemes_linux_dosbot: malware linux
{
	meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects unknown linux irc bot - 20161009"
                //Check also:
                //Samples:

        strings:
        		$irc_00 = "PING"
                $irc_01 = "PONG!"

				$x_00 = "SCANNER"
                $x_01 = "KILLATTK"
                $x_02 = "COOLMEMES"
                $x_03 = "BOTKILL"
                $x_04 = "HTTPFLOOD"

        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the irc strings
                all of ($irc_*) and 

		//Contains all of the specific strings
		all of ($x_*)
}

