rule elfiot_generic_linux_iot: malware
{
	meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects unknown linux bot - 20161009"
                //Check also:
                //Samples:

        strings:
       		$user_00 = "root"
		$user_01 = "admin"
                $user_02 = "guest"
                $user_03 = "support"

       		$pass_00 = "xc3511"
                $pass_01 = "juantech"
                $pass_02 = "xmhdipc"
                $pass_03 = "vizxv"
                $pass_04 = "bayandsl"
		$pass_05 = "123456"
                $pass_06 = "dreambox"


        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the irc strings
                2 of ($user_*) and

		//Contains all of the specific strings
		3 of ($pass_*)
}
