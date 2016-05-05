rule seven_zip_cmdversion
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.7-zip.org/download.html"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "7za"
	$s2 = "7-Zip"
	$s3 = "Usage:"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}