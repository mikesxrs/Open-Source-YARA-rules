rule crime_linux_umbreon : rootkit
{
	meta:
		description = "Catches Umbreon rootkit"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/pokemon-themed-umbreon-linux-rootkit-hits-x86-arm-systems"
		author = "Fernando Merces, FTR, Trend Micro"
		date = "2016-08"
	
	strings:
		$ = { 75 6e 66 75 63 6b 5f 6c 69 6e 6b 6d 61 70 }
		$ = "unhide.rb" ascii fullword
		$ = "rkit" ascii fullword

	condition:
		uint32(0) == 0x464c457f // Generic ELF header
		and uint8(16) == 0x0003 // Shared object file
		and all of them
}

rule crime_linux_umbreon_strace : rootkit
{
	meta:
		description = "Catches Umbreon strace rootkit component"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/pokemon-themed-umbreon-linux-rootkit-hits-x86-arm-systems"
		author = "Fernando Merces, FTR, Trend Micro"
		date = "2016-08"
	
	strings:
		$ = "LD_PRELOAD" fullword
		$ = /ld\.so\.[a-zA-Z0-9]{7}/ fullword
		$ = "\"/etc/ld.so.preload\"" fullword
		$ = "fputs_unlocked" fullword

	condition:
		uint32(0) == 0x464c457f // Generic ELF header
		and uint8(16) == 0x0003 // Shared object file
		and all of them
}

rule crime_linux_umbreon_espeon : rootkit backdoor
{
	meta:
		description = "Catches Umbreon strace rootkit component"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/pokemon-themed-umbreon-linux-rootkit-hits-x86-arm-systems"
		author = "Fernando Merces, FTR, Trend Micro"
		date = "2016-08"

	strings:
		$ = "Usage: %s [interface]" fullword
		$ = "Options:" fullword
		$ = "    interface    Listen on <interface> for packets." fullword
		$ = "/bin/espeon-shell %s %hu"
		$ = { 66 75 63 6b 20 6f 66 66 20 63 75 6e 74 }
		$ = "error: unrecognized command-line options" fullword

	condition:
		uint32(0) == 0x464c457f // Generic ELF header
		and uint8(16) == 0x0002 // Executable file
		and all of them
}