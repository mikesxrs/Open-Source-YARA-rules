rule Meterpreter_rev_tcp
{
        meta:
                description = "Meterpreter reverse TCP"
                reference = "https://www.securityartwork.es/2015/03/20/deteccion-de-codigo-malicioso-con-yara-i/"
        strings:
		$ metadata "ab.exe" wide nocase
		$ dll1 = "MSVCRT.dll" nocase
		$ dll2 = "KERNEL32.dll" nocase
		$ dll3 = "ADVAPI32.dll" nocase
		$ dll4 = "WSOCK32.dll" nocase
		$ dll5 = "WS2_32.dll" nocase
		$ dll6 = "ntdll.dll" nocase
        condition:
              #metadata == 2 and all of ($ dll *)
}
