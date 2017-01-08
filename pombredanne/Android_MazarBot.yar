import "androguard"

rule Android_MazarBot
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects MazarBot"
		source = "https://heimdalsecurity.com/blog/security-alert-new-android-malware-post-denmark/"

	condition:
		(androguard.filter(/wakeup/i) and 
		 androguard.filter(/reportsent/i)) or
		(androguard.filter(/wakeup/i) and 
		 androguard.filter(/com\.whats\.process/i))
}
