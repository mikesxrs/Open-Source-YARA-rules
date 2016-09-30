rule TrojanWin32RovnixSample
{
	meta:
		Description  = "Trojan.Rovnix.sm"
		ThreatLevel  = "5"
	strings:
		$ = "dropper.exe" ascii wide
		$ = "dropper_x64.exe" ascii wide
		$ = "Inject64Start" ascii wide
		$ = "Inject64End" ascii wide
		$ = "Inject64Normal" ascii wide
		$ = "inject_section" ascii wide
		$ = "inject_event" ascii wide
		$ = "0:/plugins/%s" ascii wide
		$ = "0:/plugins/base" ascii wide
		$ = "0:/plugins/base/binary" ascii wide
		$ = "0:/plugins/base/mask" ascii wide
		$ = "0:/plugins/base/version" ascii wide
		$ = "0:/plugins/base/once" ascii wide
		$ = "0:/plugins/rootkit" ascii wide
		$ = "0:/plugins/rootkit/binary" ascii wide
		$ = "0:/plugins/rootkit/version" ascii wide
		$ = "0:/plugins/rootkit/binary" ascii wide
		$ = "0:\\storage\\keylog" ascii wide
		$ = "0:\\storage\\config" ascii wide
		$ = "0:\\storage\\intrnl" ascii wide
		$ = "0:\\storage\\passw" ascii wide
		$ = "0:\\storage\\hunter" ascii wide
		$ = "0:/hidden" ascii wide
		$ = "0:/hidden/%s" ascii wide
		$ = "0:/hidden/%s/path" ascii wide
		$ = "0:/hidden/%s/binary" ascii wide
		$ = "0:/hidden/%s/mask" ascii wide
	condition:
		3 of them
}