rule MalwarePowerLoaderSample
{
	meta:
		Description  = "Trojan.PowerLoader.sm"
		ThreatLevel  = "5"

	strings:
		$str_1 = "powerloader" ascii wide

		$ = "inject64_section" ascii wide
		$ = "inject64_event" ascii wide
		$ = "inject_section" ascii wide
		$ = "inject_event" ascii wide
		$ = "loader.dat" ascii wide
		$ = "Inject64End" ascii wide
		$ = "Inject64Normal" ascii wide
		$ = "Inject64Start" ascii wide
		$ = "UacInject64End" ascii wide
		$ = "UacInject64Start" ascii wide
	condition:
		(2 of them) or (any of ($str_*))
}