rule apt_duqu2_drivers {

meta:

		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 drivers"
		last_modified = "2015-06-09"
		version = "1.0"
		Reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"

strings:

		$a1="\\DosDevices\\port_optimizer" wide nocase
		$a2="romanian.antihacker"
		$a3="PortOptimizerTermSrv" wide
		$a4="ugly.gorilla1"

		$b1="NdisIMCopySendCompletePerPacketInfo"
		$b2="NdisReEnumerateProtocolBindings"
		$b3="NdisOpenProtocolConfiguration"

condition:

		uint16(0) == 0x5A4D and (any of ($a*) ) and (2 of ($b*)) and filesize < 100000

}