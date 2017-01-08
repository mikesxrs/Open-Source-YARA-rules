rule jellyfish_gpu_rootkit_server: malware linux rootkit
{
meta:
	author = "@h3x2b <tracker@h3x.eu>"
	description = "Detects Jellyfish samples - 201505"
	//Check also:
	//http://tracker.h3x.eu/corpus/690
	//http://tracker.h3x.eu/info/690
	//Samples:
	//057a8ff761b5768f1fa82a463d2bdbf8  jellyfish-master.zip

strings:
	$m_01 = "gpu.txt"

	$o_01 = "socket failed!"
	$o_02 = "couldn't bind socket!"
	$o_03 = "couldn't setup listener socket!"
	$o_04 = "accept() socket failed!"
	$o_05 = "recv() failed! trying again...\n"
	$o_06 = "%s  |  Logged to gpu.txt\n"

condition:
	//ELF magic
	uint32(0) == 0x464c457f and

	//Contains all mandatory strings
	all of ($m_*) and

	//Contains some optional strings
	4 of ($o_*)

}


