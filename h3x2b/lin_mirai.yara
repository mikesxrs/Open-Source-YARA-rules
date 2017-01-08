rule mirai_20161004 : malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects Mirai samples - 20161004"
                //Check also:
                //http://tracker.h3x.eu/corpus/680
                //http://tracker.h3x.eu/info/680
                //http://blog.malwaremustdie.org/2016/08/mmd-0056-2016-linuxmirai-just.html

        strings:
                $mirai_00 = "/dev/null"
		$mirai_01 = "LCOGQGPTGP"


        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the strings
                all of ($mirai_*)
}
