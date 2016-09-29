rule shylock :  banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Shylock Banker"
		date = "2013-12-12" 
		version = "1.0" 
		ref1 = "http://iocbucket.com/iocs/1b4660d57928df5ca843c21df0b2adb117026cba"
		ref2 = "http://www.trusteer.com/blog/merchant-fraud-returns-%E2%80%93-shylock-polymorphic-financial-malware-infections-rise"
		ref3 = "https://www.csis.dk/en/csis/blog/3811/"

	strings:
		$process1 = "MASTER"
		$process2 = "_SHUTDOWN"
		$process3 = "EVT_VNC"
		$process4 = "EVT_BACK"
		$process5 = "EVT_VNC"
		$process6 = "IE_Hook::GetRequestInfo"
		$process7 = "FF_Hook::getRequestInfo"
		$process8 = "EX_Hook::CreateProcess"
		$process9 = "hijackdll.dll"
		$process10 = "MTX_"
		$process11 = "FF::PR_WriteHook entry"
		$process12 = "FF::PR_WriteHook exit"
		$process13 = "HijackProcessAttach::*** MASTER *** MASTER *** MASTER *** %s PID=%u"
		$process14 = "HijackProcessAttach::entry"
		$process15 = "FF::BEFORE INJECT"
		$process16 = "FF::AFTER INJECT"
		$process17 = "IE::AFTER INJECT"
		$process18 = "IE::BEFORE INJECT"
		$process19 = "*** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** %s"
		$process20 = "*** LOG INJECTS *** %s"
		$process21 = "*** inject to process %s not allowed"
		$process22 = "*** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** %s"
		$process23 = ".?AVFF_Hook@@"
		$process24 = ".?AVIE_Hook@@"
		$process25 = "Inject::InjectDllFromMemory"
		$process26 = "BadSocks.dll"	
		$domain1 = "extensadv.cc"
		$domain2 = "topbeat.cc"
		$domain3 = "brainsphere.cc"
		$domain4 = "commonworldme.cc"
		$domain5 = "gigacat.cc"
		$domain6 = "nw-serv.cc"
		$domain7 = "paragua-analyst.cc"
		
	condition:
		3 of ($process*) or any of ($domain*)
}