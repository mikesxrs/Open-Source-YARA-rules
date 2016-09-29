rule AutoIt : packer
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "AutoIT packer"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0" 

	strings:	
		$a = "This is a compiled AutoIt script. AV researchers please email avsupport@autoitscript.com for support."

	condition:
		$a
}