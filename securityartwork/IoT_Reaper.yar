rule LinuxIoTReaper: MALW
{
meta: 
	description = "LinuxIoTReaper"
	author = "Joan Soriano / @w0lfvan"
	reference = "https://www.securityartwork.es/2017/11/06/analisis-linux-iotreaper/"
	date = "2017-10-30"
	version = "1.0"
	md5 = "95b448bdf6b6c97a33e1d1dbe41678eb"
	sha256 = "b463ca6c3ec7fa19cd318afdd2fa2365fa9e947771c21c4bd6a3bc2120ba7f28"
strings:
		$a = "weruuoqweiur.com"
		$b = "rm -f /tmp/ftpupload.sh \n"
		$c = "%02x-%02x-%02x-%02x-%02x-%02x"
	condition:
		all of them
}
