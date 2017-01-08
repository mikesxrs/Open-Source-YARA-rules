import "androguard"

rule Android_AndroRat
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-July-2016"
		description = "This rule will be able to tag all the AndroRat samples."
		source = "http://www.symantec.com/connect/nl/blogs/remote-access-tool-takes-aim-android-apk-binder"

	condition:
		androguard.service(/my.app.client/i) and
        androguard.receiver(/BootReceiver/i) and
		androguard.filter(/android.intent.action.BOOT_COMPLETED/i)
}
