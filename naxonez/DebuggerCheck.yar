rule DebuggerCheck__API : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="IsDebuggerPresent"
	condition:
		any of them
}

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="IsDebugged"
	condition:
		any of them
}

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="NtGlobalFlags"
	condition:
		any of them
}

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="QueryInformationProcess"
	condition:
		any of them
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="CheckRemoteDebuggerPresent"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
rule DebuggerHiding__Thread : AntiDebug DebuggerHiding {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="SetInformationThread"
	condition:
		any of them
}

rule DebuggerHiding__Active : AntiDebug DebuggerHiding {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="DebugActiveProcess"
	condition:
		any of them
}

rule DebuggerTiming__PerformanceCounter : AntiDebug DebuggerTiming {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="QueryPerformanceCounter"
	condition:
		any of them
}

rule DebuggerTiming__Ticks : AntiDebug DebuggerTiming {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="GetTickCount"
	condition:
		any of them
}

rule DebuggerOutput__String : AntiDebug DebuggerOutput {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="OutputDebugString"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
rule DebuggerException__UnhandledFilter : AntiDebug DebuggerException {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="SetUnhandledExceptionFilter"
	condition:
		any of them
}

rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="GenerateConsoleCtrlEvent"
	condition:
		any of them
}

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="SetConsoleCtrlHandler"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
rule ThreadControl__Context : AntiDebug ThreadControl {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="SetThreadContext"
	condition:
		any of them
}

rule DebuggerCheck__DrWatson : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="__invoke__watson"
	condition:
		any of them
}

rule SEH__v3 : AntiDebug SEH {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = "____except__handler3"
		$ = "____local__unwind3"
	condition:
		any of them
}

rule SEH__v4 : AntiDebug SEH {
    // VS 8.0+
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = "____except__handler4"
		$ = "____local__unwind4"
		$ = "__XcptFilter"
	condition:
		any of them
}

rule SEH__vba : AntiDebug SEH {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = "vbaExceptHandler"
	condition:
		any of them
}

rule SEH__vectored : AntiDebug SEH {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = "AddVectoredExceptionHandler"
		$ = "RemoveVectoredExceptionHandler"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////// Patterns
rule DebuggerPattern__RDTSC : AntiDebug DebuggerPattern {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = {0F 31}
	condition:
		any of them
}

rule DebuggerPattern__CPUID : AntiDebug DebuggerPattern {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = {0F A2}
	condition:
		any of them
}

rule DebuggerPattern__SEH_Saves : AntiDebug DebuggerPattern {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = {64 ff 35 00 00 00 00}
	condition:
		any of them
}

rule DebuggerPattern__SEH_Inits : AntiDebug DebuggerPattern {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = {64 89 25 00 00 00 00}
	condition:
		any of them
}

