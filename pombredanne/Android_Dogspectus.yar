import "androguard"

rule Android_Dogspectus
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "20-July-2016"
		description = "This rule try to detects Dogspectus"
		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"

	condition:
		androguard.activity(/PanickedActivity/i) and 
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i) and 
		androguard.permission(/android.permission.INTERNET/i) and
		androguard.permission(/android.permission.WAKE_LOCK/i)
}
