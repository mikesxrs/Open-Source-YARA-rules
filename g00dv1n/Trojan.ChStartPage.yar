rule TrojanChangeStartPageSampleA
{
 meta:
  Description  = "Trojan.CStartPage.sm"
  ThreatLevel  = "5"

 strings:
	$ = "chrome.exe" ascii wide
	$ = "urls_to_restore_on_startup" ascii wide
	$ = "restore_on_startup" ascii wide
	$ = "restore_on_startup_migrated" ascii wide
	$ = "urls_to_restore_on_startup" ascii wide
	$ = "translate_accepted_count" ascii wide
	$ = "translate_denied_count" ascii wide
	$ = "translate_site_blacklist" ascii wide
	$ = "netsh firewall add allowedprogram" ascii wide
	$ = "homepage_is_newtabpage" ascii wide
	$ = "Start Page" ascii wide
	$ = "user_pref(%cbrowser.startup.homepage%c" ascii wide
	$ = "%ws\\mozilla\\firefox\\profiles" ascii wide
	$ = "c:\\windows\\sms.exe" ascii wide
 condition:
	3 of them
}
