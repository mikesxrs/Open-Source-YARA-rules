rule PM_docx_with_vba_bin
{
meta:
    author="R.Tokazowski"
    company="PhishMe, Inc."
    URL="http://phishme.com/ms-word-macros-now-social-engineering-malware"

strings:
	$a1 = "PK"
	$a2 = "word/_rels/vbaProject.bin"
	
condition:
	$a1 at 0 and $a2
}