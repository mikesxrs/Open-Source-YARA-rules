rule Dexter
{
meta:
	description = "Dexter malware memory injection detection"
	in_the_wild = true

strings:
$a = "Resilience"
$b = "download-"
$c = "update-"
$d = "checkin:"
$e = "uninstall"
$f = "CurrentVersion\\Run"
$g = "response="
$h = "gateway.php"
$i = "iexplore.exe"

condition:

all of them

}
