rule Tenablebot
{
	meta:
		author = "tenable"
		reference = "https://www.tenable.com/blog/threat-hunting-with-yara-and-nessus"
	strings:
		$channel = "#secret_tenable_bot_channel"
		$version = "Tenable Bot version 0.1"
		$version_command = "!version"
		$exec_command = "!exec"
		$user = "USER tenable_bot 8 * :doh!"
	condition:
		all of them
}