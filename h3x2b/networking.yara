import "pe"

//Detect capabilities of opening network sockets

rule winsocks : feature networking windows
{
meta:
	description = "Imports Winsock Library"

condition:
	// MZ at the beginning of file
        uint16(0) == 0x5a4d and

	pe.imports("wsock32.dll","WSAStartup") and
	pe.imports("wsock32.dll","socket")
}




