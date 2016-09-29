rule PM_Dyre_Voice_Message
{
meta:
	author="R.Tokazowski"
	company="PhishMe, Inc."
	URL="http://phishme.com/two-attacks-two-dyres-infrastructure/"


strings:
	$s1 = "voice message" nocase
	$s2 = "voice redirected message" nocase
	$s3 = "sent: " nocase

condition:
	2 of them
}