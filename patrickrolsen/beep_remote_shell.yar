rule beep_remote_shell
{
	meta:
	author = "@patrickrolsen"
	reference = "0625b5b010a1acb92f02338b8e61bb34"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$mz = { 4d 5a }
	$s1 = "%s\\admin$\\system32\\%s"
	$s2 = "BeepService"
	$s3 = "In ControlService"
	$s4 = "In OpenScManager"
	$s5 = "In CreateService"
	$s6 = "Service is RUNNING"
	$s7 = "Service is not running"
	$s8 = "In DeleteService"
	$s9 = "Remove the service OK"
condition:
	($mz at 0) and (all of ($s*))
}