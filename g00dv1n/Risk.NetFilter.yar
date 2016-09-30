rule RiskNetFilterSampleA
{
	meta:
		Description  = "Risk.NetFilter.A.vb"
		ThreatLevel  = "5"

	strings:

		$ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\epfwwfp" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\epfwwfpr" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\nisdrv" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\symnets" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\klwfp" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\amoncdw8" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\amoncdw7" ascii wide
        $ = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\bdfwfpf_pc" ascii wide
        $ = "NFSDK Flow Established Callout" ascii wide
        $ = "Flow Established Callout" ascii wide
        $ = "NFSDK Stream Callout" ascii wide
        $ = "Stream Callout" ascii wide
        $ = "\\Device\\CtrlSM" ascii wide
        $ = "\\DosDevices\\CtrlSM" ascii wide

	condition:
		all of them
}
