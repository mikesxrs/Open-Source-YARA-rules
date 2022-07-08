import "pe"
import "hash"

rule sta_Voltron_0xFancyFilter_broad
{
	meta:
		desc = "Experimental approaches to detecting 0xFancyFilter features"
		author = "JAG-S"
		canary = "passed"
		version = "5"
		last_modified = "02.25.2021"
		hash1 = "ef35705696d78cc9f4de6adad2cbe5ed22fd50da0ce4180c1d47cf0536aebc87"
		hash2 = "df4bc387181ffaabe0be39e66ef5eb838ed638e0ae2b82e9a7daa83647e38bb1"
		hash3 = "cd3ee807e349abae65d93e421176f302528b739e9e1d77a6ce4e57caeec91b4e"
		hash4 = "369145c6f366f25a4e8878ad1ffec73d680cdc2da4380b221d1d7cdf3a90c930"
	strings:
		$a1 = "mJzTmRichKzTm" ascii wide
		$a2 = "@+aC@+a1@+aT@+a" ascii wide
		$a3 = "?nothrow@std@@3Unothrow_t@1@B" ascii wide
		$a4 = "IEIsProtectedModeProcess" ascii wide

		$spec1 = "htmlfiltxx64.dll" ascii wide
		$spec2 = "Microsoft (R) html: Protocol Filter" ascii wide
		$spec3 = "htmlfilt.dat" ascii wide
		//$spec5 = "htmlfilt.dll" ascii wide //FP w Tracked PSP
		$spec6 = "http: Asynchronous Pluggable Protocol Filter" ascii wide

		//Potential FPs?
		$urlPrep1 = "&MetaCredentials=" ascii wide
		$urlPrep2 = "&HashedCredentials=" ascii wide
		$urlPrep3 = "&AuthRev=" ascii wide
		$urlPrep4 = "&AuthType=" ascii wide
		$urlPrep5 = "SessionId=" ascii wide
		$urlPrep6 = "&SessionHd=%hs" ascii wide
		$urlPrep7 = "?SessionId=%hs" ascii wide
		
		$clsid1 = { C2 35 31 5E 4C 91 FB BE 2E B4 4F 5B 05 }
		$clsid2 = { CE F0 73 15 47 BF 7C 35 C1 B8 1F A2 2F }

		$named_pipe1 = "pipe\\\\smeg_request" ascii wide
		$named_pipe2 = "pipe\\smeg_response" ascii wide

		$regKey1 = "Software\\Classes\\CLSID\\%ls" ascii wide
		$regKey2 = "Software\\Classes\\PROTOCOLS\\Filter\\text/html" ascii wide
		$regKey3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections" ascii wide
		$regKey4 = "Software\\Microsoft\\Internet Explorer\\LowRegistry\\Extensions" ascii wide
		$urlFilter1 = "UrlFilterState" ascii wide
		$urlFilter2 = "Use_UrlFilter" ascii wide
		$urlFilter3 = "UrlFiltering" ascii wide
		
		// FPs?
		$dllLoad1 = "rundll32 %s,Entry %hs" ascii wide
		$dllLoad2 = "cmd /c %hs" ascii wide
		$dllLoad3 = "dllhost.exe" ascii wide

		$oddities1 = "<UGH>" ascii wide
		$oddities2 = "%d:%d:%d/%d:%d:%d" ascii wide
		$oddities3 = "%d:%d:%d" ascii wide
		$oddities4 = "%5d, (%5d), %ls" ascii wide
		$oddities5 = "er.dat" ascii wide

	condition:
		uint16(0) == 0x5a4d
		and
		(
			3 of ($a*)
			or
			any of ($spec*)
			or
			any of ($clsid*)
			or
			any of ($named_pipe*)
			or
			3 of ($regKey*)
			or
			all of ($urlPrep*)
			or
			(2 of ($regKey*) and 2 of ($urlFilter*))
			or
			all of ($dllLoad*)
			or
			4 of ($oddities*)
			or
			for any i in (0..pe.number_of_resources - 1):
			(
				hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "a37b63630a720111cac4be52aee1169524ccd2ac965bdc0b13b43190d33ceb13"
				or
				hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "42aa5bf31183db59b4d67bb560c5bec823d6a6d6a937bb1086b350aa8739ad27"
			)
			or
			pe.rich_signature.clear_data == "DanS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc3\x0f`\x00\x01\x00\x00\x00{\x1c\x0c\x00\x02\x00\x00\x00\xc3\x0f\x0f\x00\x02\x00\x00\x00\xc3\x0f_\x00\x09\x00\x00\x00\x00\x00\x01\x00\xa1\x00\x00\x00\xc3\x0f]\x00\x11\x00\x00\x00\xfa#@\x00\x01\x00\x00\x00\x09x\x8a\x00\x16\x00\x00\x00\x09x\x92\x00\x01\x00\x00\x00\x1eR\x94\x00\x01\x00\x00\x00\x09x\x91\x00\x01\x00\x00\x00"
			or
			/*
			for any i in (0..pe.number_of_resources - 1):
			(
				pe.resources[i].type_string == "X\x00"
				and
				pe.resources[i].language == 1033
			)
			 // Interesting feature but it does FP.
			or*/
			pe.imphash() == "e4f7691d7707944196d03353d13b963e"
			or
			pe.version_info["FileDescription"] contains "Microsoft (R) html:"
		)
}

Footer
© 2022 GitHub, Inc. 
