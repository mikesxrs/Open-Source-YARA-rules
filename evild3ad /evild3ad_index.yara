import "pe"

rule Contains_ah_encoded_PE_file
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect an &H encoded executable"
		method = "&Hxx is the hexadecimal notation for a byte in VBA"
		reference = "https://blog.didierstevens.com/2014/12/23/oledump-extracting-embedded-exe-from-doc/"
		hash = "6a574342b3e4e44ae624f7606bd60efa"
		date = "2016-04-23"

	strings:
		$MZ = "&H4d&H5a" nocase // DOS header signature in e_magic
		$DOS = "&H21&H54&H68&H69&H73&H20&H70&H72&H6f&H67&H72&H61&H6d&H20&H63&H61&H6e&H6e&H6f&H74&H20&H62&H65&H20&H72&H75&H6e&H20&H69&H6e&H20&H44&H4f&H53&H20&H6d&H6f&H64&H65&H2e" nocase // !This program cannot be run in DOS mode. (DOS stub)
		$PE = "&H50&H45&H00&H00" nocase // PE signature at start of PE header (NtHeader)

	condition:
		$MZ and $DOS and $PE
}

rule Contains_ASCII_Hex_encoded_PE_file
{
    meta:
        author = "Martin Willing (https://evild3ad.com)"
        description = "Detect an ASCII Hex encoded executable"
		reference = "https://blogs.mcafee.com/mcafee-labs/w97m-downloader-serving-vawtrak/"
		hash = "e56a57acf528b8cd340ae039519d5150"
		date = "2016-03-28"
		
    strings:
		$MZ = "4D5A" nocase // DOS header signature in e_magic
		$DOS = "21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6f64652E" nocase // !This program cannot be run in DOS mode. (DOS stub)
		$PE = "50450000" nocase // PE signature at start of PE header (NtHeader)
		
    condition:
		$MZ and $DOS and $PE

}

rule Contains_hidden_PE_File_inside_a_sequence_of_numbers
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect a hidden PE file inside a sequence of numbers (comma separated)"
		reference = "http://blog.didierstevens.com/2016/01/07/blackenergy-xls-dropper/"
		reference = "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/"
		date = "2016-01-09"
		filetype = "decompressed VBA macro code"
		
	strings:
		$a = "= Array(" // Array of bytes
		$b = "77, 90," // MZ
		$c = "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46," // !This program cannot be run in DOS mode.
	
	condition:
	 	all of them
}

rule Contains_UserForm_Object_1
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document. Attackers use UserForm objects to obfuscate their scripts and malicious code."
		alert = "May used to store a URL as a property of a userform"
		reference = "https://isc.sans.edu/forums/diary/Tip+Quick+Analysis+of+Office+Maldoc/20751/"
		reference = "http://blog.didierstevens.com/2016/03/11/update-oledump-py-version-0-0-23/"
		hash = "4e0c55054c4f7c32aece5cfbbea02846"
		date = "2016-03-11"
		filetype = "Office documents"
		
	strings:
		
		$a = "Microsoft Forms 2.0" // Forms
		$b = "http"
	
	condition:
	 	all of them
}

rule Contains_UserForm_Object_2
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document. Attackers use UserForm objects to obfuscate their scripts and malicious code."
		alert = "May used to store malicious code in a UserForm object embedded in a form object"
		reference = "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx"
		hash = "3c013125ffe34b81e39f92b59ca26b6c"
		date = "2016-03-11"
		filetype = "Office documents"
		
	strings:
		
		$a = "Microsoft Forms 2.0" // Forms
		$b = "UserForm1" // UserForm
	
	condition:
	 	all of them
}

rule Contains_UserForm_Object_3
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document. Attackers use UserForm objects to obfuscate their scripts and malicious code."
		alert = "May used to store malicious code in a TextBox1 object embedded in a form object"
		reference = "https://blogs.mcafee.com/mcafee-labs/macro-malware-associated-dridex-finds-new-ways-hide/"
		hash = "13d4e6f0f7dc15ba17df91954de0b01d"
		date = "2016-03-11"
		filetype = "Office documents"
		
	strings:
		
		$a = "Microsoft Forms 2.0" // Forms
		$b = "UserForm1" // UserForm
		$c = "TextBox1" // Control
	
	condition:
	 	all of them
}
rule Contains_VBA_macro_code
{
	meta:
		author = "evild3ad"
		description = "Detect a MS Office document with embedded VBA macro code"
		date = "2016-01-09"
		filetype = "Office documents"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F } // Attribute VB_

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}
rule MIME_MSO_ActiveMime_base64
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect MIME MSO Base64 encoded ActiveMime file"
		date = "2016-02-28"
		filetype = "Office documents"
		
	strings:
		$mime = "MIME-Version:"
		$base64 = "Content-Transfer-Encoding: base64"
		$mso = "Content-Type: application/x-mso"
		//$activemime = /Q(\x0D\x0A|)W(\x0D\x0A|)N(\x0D\x0A|)0(\x0D\x0A|)a(\x0D\x0A|)X(\x0D\x0A|)Z(\x0D\x0A|)l(\x0D\x0A|)T(\x0D\x0A|)W/
	
	condition:
		$mime at 0 and $base64 and $mso //and $activemime
}

