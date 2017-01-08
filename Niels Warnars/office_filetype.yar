rule doc
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word 2003 file format detection"
	strings:
		$header = { D0 CF 11 E0 A1 B1 1A E1 }
		$str1 = "Microsoft Office Word"
		$str2 = "MSWordDoc"
		$str3 = "Word.Document.8"
	condition:
	   $header at 0 and any of ($str*) 
}

rule ppt
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "PowerPoint 2003 file format detection"
	strings:
		$header = { D0 CF 11 E0 A1 B1 1A E1 }
		$str = "Microsoft Office PowerPoint"
	condition:
	   $header at 0 and $str
}

rule xls
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel 2003 file format detection"
	strings:
		$header = { D0 CF 11 E0 A1 B1 1A E1 }
		$str1 = "Microsoft Excel"
		$str2 = "Excel.Sheet.8"
	condition:
	   $header at 0 and any of ($str*) 
}

rule docx
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word 2007 file format detection"
	strings:
		$header = { 50 4B 03 04 }
		$str = "document.xml"
	condition:
	   $header at 0 and $str
}

rule pptx
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "PowerPoint 2007 file format detection"
	strings:
		$header = { 50 4B 03 04 }
		$str = "presentation.xml"
	condition:
	   $header at 0 and $str
}

rule xlsx
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel 2007 file format detection"
	strings:
		$header = { 50 4B 03 04 }
		$str = "workbook.xml"
	condition:
	   $header at 0 and $str
}

rule xlsb
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel Binary Workbook file format detection"

	strings:
		$header = { 50 4B 03 04 }
		$str = "workbook.bin"
	condition:
	   $header at 0 and $str
}

rule rtf
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word RTF file format detection"
	strings:
		$header = "{\\rt"	
	condition:
	   $header at 0
}

rule word_xml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word XML file format detection"
	strings:
		$header = "<?xml"
		$str = "<?mso-application progid=\"Word.Document\"?>"
	condition:
	   $header at 0 and $str
}

rule ppt_xml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "PowerPoint XML file format detection"
	strings:
		$header = "<?xml"
		$str = "<?mso-application progid=\"PowerPoint.Show\"?>"
	condition:
	   $header at 0 and $str
}

rule excel_xml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel XML file format detection"
	strings:
		$header = "<?xml"
		$str = "<?mso-application progid=\"Excel.Sheet\"?>"
	condition:
	   $header at 0 and $str
}

rule mhtml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word/Excel MHTML file format detection"
	strings:
		$str1 = "MIME-Version:"
		$str2 = "Content-Location:"
		$email_str1 = "From:"
		$email_str2 = "Subject:"
	condition:
		all of ($str*) and not any of ($email_str*)
}
