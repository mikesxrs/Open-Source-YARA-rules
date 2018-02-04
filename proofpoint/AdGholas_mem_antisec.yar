rule AdGholas_mem_antisec
{
 meta:
     malfamily = "AdGholas"
	 author = "Proofpoint"
	 reference = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"
	 reference2 = "https://blog.malwarebytes.com/cybercrime/exploits/2016/12/adgholas-malvertising-business-as-usual/"


 strings:
     $vid1 = "res://c:\\windows\\system32\\atibtmon.exe" nocase ascii wide
     $vid2 = "res://c:\\windows\\system32\\aticfx32.dll" nocase ascii wide
     $vid3 = "res://c:\\windows\\system32\\drivers\\ati2mtag.sys" nocase ascii wide
     $vid4 = "res://c:\\windows\\system32\\drivers\\atihdmi.sys" nocase ascii wide
     $vid5 = "res://c:\\windows\\system32\\drivers\\atikmdag.sys" nocase ascii wide
     $vid6 = "res://c:\\windows\\system32\\drivers\\igdkmd32.sys" nocase ascii wide
     $vid7 = "res://c:\\windows\\system32\\drivers\\igdkmd64.sys" nocase ascii wide
     $vid8 = "res://c:\\windows\\system32\\drivers\\igdpmd32.sys" nocase ascii wide
     $vid9 = "res://c:\\windows\\system32\\drivers\\igdpmd64.sys" nocase ascii wide
     $vid10 = "res://c:\\windows\\system32\\drivers\\mfeavfk.sys" nocase ascii wide
     $vid11 = "res://c:\\windows\\system32\\drivers\\mfehidk.sys" nocase ascii wide
     $vid12 = "res://c:\\windows\\system32\\drivers\\mfenlfk.sys" nocase ascii wide
     $vid13 = "res://c:\\windows\\system32\\drivers\\nvhda32v.sys" nocase ascii wide
     $vid14 = "res://c:\\windows\\system32\\drivers\\nvhda64v.sys" nocase ascii wide
     $vid15 = "res://c:\\windows\\system32\\drivers\\nvlddmkm.sys" nocase ascii wide
     $vid16 = "res://c:\\windows\\system32\\drivers\\pci.sys" nocase ascii wide
     $vid17 = "res://c:\\windows\\system32\\igd10umd32.dll" nocase ascii wide
     $vid18 = "res://c:\\windows\\system32\\igd10umd64.dll" nocase ascii wide
     $vid19 = "res://c:\\windows\\system32\\igdumd32.dll" nocase ascii wide
     $vid20 = "res://c:\\windows\\system32\\igdumd64.dll" nocase ascii wide
     $vid21 = "res://c:\\windows\\system32\\igdumdim32.dll" nocase ascii wide
     $vid22 = "res://c:\\windows\\system32\\igdumdim64.dll" nocase ascii wide
     $vid23 = "res://c:\\windows\\system32\\igdusc32.dll" nocase ascii wide
     $vid24 = "res://c:\\windows\\system32\\igdusc64.dll" nocase ascii wide
     $vid25 = "res://c:\\windows\\system32\\nvcpl.dll" nocase ascii wide
     $vid26 = "res://c:\\windows\\system32\\opencl.dll" nocase ascii wide
     $antisec = /res:\/\/(c:\\((program files|programme|archivos de programa|programmes|programmi|arquivos de programas|program|programmer|programfiler|programas|fisiere program)( (x86)\\((p(rox(y labs\\proxycap\\pcapui|ifier\\proxifier)|arallels\\parallels tools\\prl_cc)|e(met (5.[012]|4.[01])\\emet_gui|ffetech http sniffer\\ehsniffer)|malwarebytes anti-(exploit\\mbae|malware\\mbam)|oracle\\virtualbox guest additions\\vboxtray|debugging tools for windows (x86)\\windbg|(wireshark\\wiresha|york\\yo)rk|ufasoft\\sockschain\\sockschain|vmware\\vmware tools\\vmtoolsd|nirsoft\\smartsniff\\smsniff|charles\\charles).exe|i(n(vincea\\((browser protection\\invbrowser|enterprise\\invprotect).exe|threat analyzer\\fips\\nss\\lib\\ssl3.dll)|ternet explorer\\iexplore.exe)|einspector\\(httpanalyzerfullv(6\\hookwinsockv6|7\\hookwinsockv7)|iewebdeveloperv2\\iewebdeveloperv2).dll)|geo(edge\\geo(vpn\\bin\\geovpn|proxy\\geoproxy).exe|surf by biscience toolbar\\tbhelper.dll)|s(oftperfect network protocol analyzer\\snpa.exe|andboxie\\sbiedll.dll)|(adclarity toolbar\\tbhelper|httpwatch\\httpwatch).dll|fiddler(coreapi\\fiddlercore.dll|2?\\fiddler.exe))|\\((p(rox(y labs\\proxycap\\pcapui|ifier\\proxifier)|arallels\\parallels tools\\prl_cc)|e(met (5.[012]|4.[01])\\emet_gui|ffetech http sniffer\\ehsniffer)|malwarebytes anti-(exploit\\mbae|malware\\mbam)|oracle\\virtualbox guest additions\\vboxtray|debugging tools for windows (x86)\\windbg|(wireshark\\wiresha|york\\yo)rk|ufasoft\\sockschain\\sockschain|vmware\\vmware tools\\vmtoolsd|nirsoft\\smartsniff\\smsniff|charles\\charles).exe|i(nvincea\\((browser protection\\invbrowser|enterprise\\invprotect).exe|threat analyzer\\fips\\nss\\lib\\ssl3.dll)|einspector\\(httpanalyzerfullv(6\\hookwinsockv6|7\\hookwinsockv7)|iewebdeveloperv2\\iewebdeveloperv2).dll)|geo(edge\\geo(vpn\\bin\\geovpn|proxy\\geoproxy).exe|surf by biscience toolbar\\tbhelper.dll)|s(oftperfect network protocol analyzer\\snpa.exe|andboxie\\sbiedll.dll)|(adclarity toolbar\\tbhelper|httpwatch\\httpwatch).dll|fiddler(coreapi\\fiddlercore.dll|2?\\fiddler.exe)))|windows\\system32\\(drivers\\(tm(actmon|evtmgr|comm|tdi)|nv(hda(32|64)v|lddmkm)|bd(sandbox|fsfltr)|p(ssdklbf|rl_fs)|e(amonm?|hdrv)|v(boxdrv|mci)|hmpalert).sys|(p(rxerdrv|capwsp)|socketspy).dll|v(boxservice|mu?srvc).exe)|python(3[45]|27)\\python.exe)|(h(ookwinsockv[67]|ttpwatch)|s(b(ie|ox)dll|ocketspy)|p(rxerdrv|capwsp)|xproxyplugin|mbae).dll|inv(guestie.dll(\/icon.png)?|redirhostie.dll)|w\/icon.png)/ nocase ascii wide

 condition:
      any of ($vid*) and #antisec > 20
}
