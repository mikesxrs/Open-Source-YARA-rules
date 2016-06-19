rule xmlshell{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "21/09/2015"
    description = "strings within XMLShell used by CommentCrew"
strings:
	$STFail = "ST fail"
	$STSucc = "ST Success"
	$Proc = "Process cmd.exe exited"
	$ShellSuccess = "Shell started successfully"
	$ShellFail = "Shell started fail"
	$KillFail = "Kill Fail"
	$KillSucc = "Kill Success"
condition:
	all of them
}
