import "pe"
rule Check_Wine
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of Wine"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$wine = "wine_get_unix_file_name"
	condition:
		$wine and pe.imports("kernel32.dll","GetModuleHandleA")
}