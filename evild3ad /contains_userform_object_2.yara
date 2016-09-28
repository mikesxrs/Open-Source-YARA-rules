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
