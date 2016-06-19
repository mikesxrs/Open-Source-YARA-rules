rule dbgdetect_funcs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$func1 = "IsDebuggerPresent"
		$func2 = "OutputDebugString"
		$func3 = "ZwQuerySystemInformation"
		$func4 = "ZwQueryInformationProcess"
		$func5 = "IsDebugged"
		$func6 = "NtGlobalFlags"
		$func7 = "CheckRemoteDebuggerPresent"
		$func8 = "SetInformationThread"
		$func9 = "DebugActiveProcess"

	condition:
		2 of them
}

