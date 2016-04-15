rule PM_Dyre_Delivery : dyre cryptowall crimeware
{
meta:
	author="R.Tokazowski"
	company="PhishMe, Inc."
	URL="http://phishme.com/two-attacks-two-dyres-infrastructure/"

strings:
	$domain1 = "goo.gl" nocase
	$domain2 = "cubby.com" nocase
	$domain3 = "dropbox.com" nocase

	$subject1 = "fax message" nocase
	$subject2 = "new fax" nocase
	$subject3 = "fax report" nocase

	$constant = "Resolution: 400x400 DPI" nocase

condition:

	(1 of ($domain*) and 1 of ($subject*)) or ($constant)

}