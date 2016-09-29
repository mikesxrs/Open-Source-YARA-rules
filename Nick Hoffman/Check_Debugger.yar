import "pe"
rule Check_Debugger
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for both isDebuggerPresent and CheckRemoteDebuggerPresent"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	condition:
		pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") and 
		pe.imports("kernel32.dll","IsDebuggerPresent")
}