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