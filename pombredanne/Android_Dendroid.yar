import "androguard"

rule Android_Dendroid
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detect Dendroid"
		source = "https://blog.lookout.com/blog/2014/03/06/dendroid/"

	condition:
		(androguard.service(/com.connect.RecordService/i) or
		androguard.activity(/com.connect.Dendroid/i)) and
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i)
}
