rule kaiten: malware linux
{
	meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects Kaiten samples - 20161009"
                //Check also:
                //http://tracker.h3x.eu/corpus/700
                //http://tracker.h3x.eu/info/700
                //http://www.kernelmode.info/forum/viewtopic.php?f=16&t=2747
                //https://www.virustotal.com/en/file/0173924f3b91579c2ab3382333f81b09fa2653588b9595243a0d85bd97f7dd11/analysis/1409864439/
                //Samples:

        strings:
       		$kaiten_00 = "NOTICE %s :Kaiten wa goraku"
                $kaiten_01 = "NOTICE %s :TSUNAMI <target> <secs>"
                $kaiten_02 = "NOTICE %s :PAN <target> <port> <secs>"

        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the strings
                2 of ($kaiten_*)
}
