import "androguard"

rule Android_Banker_Sberbank
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android Banker Sberbank"
		source = "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"

	condition:
		androguard.service(/MasterInterceptor/i) and 
		androguard.receiver(/MasterBoot/i) and 
		androguard.filter(/ACTION_POWER_DISCONNECTED/i)
}
