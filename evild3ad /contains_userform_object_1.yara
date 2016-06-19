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