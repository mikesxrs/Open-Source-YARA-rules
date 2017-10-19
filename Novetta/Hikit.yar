
private global rule IS_PE
{
	strings:
		$dos = "MZ"  
		$pe = "PE"	
	condition:
		$dos at 0 and $pe in (200..300)
}

rule hikit_xor_decode
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"
		warning = "this signature may produce FP's against very large sets of files"

	strings:
		$Gen1 = {8B ?? 83 ?? 04 33 ?? 4? 89 ?? ?? 75 F3}
		$Gen2 = {31 ?? 83 ?? 04 (4? 75 F8 | 83 ?? 01 75 F6)}
	
	condition:
		$Gen1 or $Gen2
}


rule hikit_xor_decode_ex: APT Hikit
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$Gen1 = {(8D ?4 ?5 00 00 00 00 | 8D 41 FB C1 E8 02 40) [1-32] 8B ?? 83 ?? 04 33 ?? 4? 89 ?? ?? 75 F3}
		$Gen2 = {(8D ?4 ?5 00 00 00 00 | 8D 41 FB C1 E8 02 40) [1-32] 31 ?? 83 ?? 04 (4? 75 F8 | 83 ?? 01 75 F6)}
		
	condition:
		$Gen1 or $Gen2

}

rule zxshell_vfw
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$plug = "zxplug" ascii
		$prefix1 = "[DeskTop]" ascii
		$prefix2 = "[RDT]" ascii
		$shsl = "ShareShell" ascii

	condition:
		IS_PE and ((#plug > 2 and #shsl > 1) or (#prefix1 > 3) or (#prefix2 > 3)) 
}

rule zoxpng_uri
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$url = "png&w=800&h=600&ei=CnJcUcSBL4rFkQX444HYCw&zoom=1&ved=1t:3588,r:1,s:0,i:92&iact=rc&dur=368&page=1&tbnh=184&tbnw=259&start=0&ndsp=20&tx=114&ty=58"
	condition:
		$url
}


rule zxshell_pluginmanager
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$a1 ="%d plug-ins you add the command" fullword
		$a2 = "Error, the plugin is not loaded." fullword
		$a3 = "Plug-in added successfully. %s" fullword
		$b1 = "not export zxMain func."
		$b2 = "cmd name exist, please use other."
		$b3 = "SYSTEM\\CurrentControlSet\\Control\\zxplug"
		$cmd = "zxplug"

	condition:
		#cmd > 3 and (all of ($a*) or all of ($b*))
} 

rule zxshell_transferfile_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$cmd = "TransFile"
		$s1 = "put IP port user pass localfile remotefile"
		$s2 = "get URL SaveAs"
		$s3 = "Transfer successful: %d bytes in %d millisecond."
	condition:
		#cmd > 3 and all of ($s*) 
} 

rule zxshell_shareshell_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$cmd = "ShareShell"
		$s1 = "Shared a shell to %s:%s Successfully."
		$s2 = "ShareShell 1.1.1.1 99"
	condition:
		#cmd > 1 and all of ($s*) 
} 

rule zxshell_http_proxy_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "ZxHttpProxy" nocase
		$s2 = "(All IP Is Acceptable.)"
		$s3 = "(End Proxy Service.)"
		$s4 = "(View Server Info)"

	condition:
		#s1 > 1 and all of ($s*)

}

rule zxshell_zxsocksproxy_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "ZXSocksProxy" nocase
		$s2 = "ZXSocksProxy Service Isn't Running"
		$s3 = "(View SocksProxy Server Info)"
		$s4 = "Try to change a Port and then try again."
	condition:
		#s1 > 5 and all of ($s*)
}

rule zxshell_portscan_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "================Start Scaning================" 
		$s2 = "================End================" 
		$s3 = "TCP Port MultiScanner"

	condition:
		all of them

}

rule zxshell_zxnc_module
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "ZXNC"
		$s2 = "listen mode, for inbound connects"
		$s3 = "(while in the ZXNC mode type this option to quit it.)"

	condition:
		all of them

}

rule zxshell_rootkit
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$s1 = "the end!!" fullword
		$tcpstr0 = "TCPFilter_Attach Successfully."
		$tcpstr1 = "TCPFilter_Attach: TCPFilter_Detach Finished" fullword
		$tcpstr2 = "TCPFilter_Attach: Couldn't attach to TCP Device Object"
		$output1 = "filetype[NTFS] process:[%s] is scaning file[%ws][%ws]"
		$output2 = "file protect:%ws"

	condition:
		all of ($tcpstr*) and ($s1 or $output1 or $output2)
}

rule zxshell_variant1
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"


	strings:
		$prefix1 = "[RDT] " ascii
		$prefix2 = "[DeskTop] " ascii
		$s1 = "IsThatMyMaster Error" ascii
		$s2 = "exec cmd failed :(" ascii
		$bs1 = {ff 15 70 50 00 10}
		condition:
			(#prefix1 > 3 or #prefix2 > 1) and (all of ($s*) or #bs1 > 1)
}

rule derusbi_ssl
{
	meta:
		copyright = "Novetta Solutions"
		author = "Novetta Advanced Research Group"

	strings:
		$live = "login.live.com"
		$get = {0047455420687474703A2F2F00255B5E3A5D3A256400}

	condition:
		all of them

}
