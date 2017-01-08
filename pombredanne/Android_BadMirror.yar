import "androguard"

rule Android_BadMirror
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "BadMirror is Android malware. The malware sends information to its remote CnC (phone number, MAC adddress, list of installed applications...) but it also has the capability to execute a few commands such as \"app\" (download an APK) or \"page\" (display a given URL)."
		source = "https://blog.fortinet.com/post/badmirror-new-android-malware-family-spotted-by-sherlockdroid"

	condition:
		androguard.service(/SimInsService/i) and
        androguard.permission(/android.permission.READ_PHONE_STATE/i)
}
