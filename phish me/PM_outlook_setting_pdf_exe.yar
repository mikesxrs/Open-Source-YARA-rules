rule PM_outlook_setting_pdf_exe

{
meta:
	author="R.Tokazowski"
	company="PhishMe, Inc."
	URL="http://phishme.com/evolution-upatre-dyre/"

strings:
	$a1 = "PK"
	$a2 = "outlook_setting_pdf.exe"

condition:
	$a1 at 0 and $a2

}