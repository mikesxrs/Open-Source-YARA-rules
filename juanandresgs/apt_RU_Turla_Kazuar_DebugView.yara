import "pe"
import "dotnet"

/*
	"dbgsview.exe"
	Agent.exe
	"adflctlmon.exe"
	d3429016-d029-45b8-b260-85221265838e
	76b7b11a-4124-448b-9903-15524e321f3f
	2cde886e-ee24-496a-bb31-1ced6b766ced
	imphash
	f34d5f2d4577ed6d9ceec516c1f5a744
*/

rule apt_RU_Turla_Kazuar_DebugView_peFeatures
{
	meta:
		desc = "Turla mimicking SysInternals Tools- peFeatures"
		version = "2.0"
		author = "JAG-S"
		hash = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"

	condition:
		uint16(0) == 0x5a4d
		and
		(
			pe.version_info["LegalCopyright"] == "Test Copyright" 
			and
			(
				(
				pe.version_info["ProductName"] == "Sysinternals DebugView"
				and
				pe.version_info["Description"] == "Sysinternals DebugView"
				)
			or
				(
				pe.version_info["FileVersion"] == "4.80.0.0"
				and
				pe.version_info["Comments"] == "Sysinternals DebugView"
				)
			or
				(
				pe.version_info["OriginalName"] contains "DebugView.exe"
				and
				pe.version_info["InternalName"] contains "DebugView.exe"
				)
			or
				(
				pe.version_info["OriginalName"] == "Agent.exe"
				and
				pe.version_info["InternalName"] == "Agent.exe"
				)
			)
		)
}


rule apt_RU_Turla_Kazuar_DebugView_dotnet
{
	meta:
		desc = "Turla mimicking SysInternals Tools- peFeatures"
		version = "1.0"
		author = "JAG-S"
		hash = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"
	condition:
		uint16(0) == 0x5a4d
		and
		(
			for any i in (0..dotnet.number_of_guids-1): 
			(
					dotnet.guids[i] == "d3429016-d029-45b8-b260-85221265838e"
					or
					dotnet.guids[i] == "76b7b11a-4124-448b-9903-15524e321f3f"
					or
					dotnet.guids[i] == "2cde886e-ee24-496a-bb31-1ced6b766ced"
			)
			or
			dotnet.module_name == "DebugView.exe"
		)		
}
