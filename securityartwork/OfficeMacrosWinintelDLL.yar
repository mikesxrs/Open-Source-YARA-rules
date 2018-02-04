rule OfficeMacrosWinintelDLL
{
	meta:
		Autor = "Manuel Bermudez"
		date = "08-01-2015"
		description = "Fichero office con macros sospechosa"
		link = "https://www.securityartwork.es/2015/04/17/gestion-de-incidentes-practica-actuaciones-ante-malware-ii/"
	strings:
		$VBA1 = "VBA6"
		$VBA2 = "VBA7"
		$str1 = "wininet.dll" nocase
		$str2 = "InternetOpenUrl" nocase
		$str3 = "InternetReadFile" nocase
		$str4 = "InternetOpen" nocase
 		$str5 = "InternetCloseHandle" nocase
	condition:
		1 of ($VBA*) and 2 of ($str*)
}
