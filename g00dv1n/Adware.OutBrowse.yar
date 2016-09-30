rule AdwareOutBrowseSample
{
	meta:
		Description  = "Adware.OutBrowse.vb"
		ThreatLevel  = "5"

	strings:

		$ = "cdn.install.playbryte.com" ascii wide
		$ = "download.2yourface.com" ascii wide
		$ = "www.default-page.com" ascii wide
		$ = "install2.optimum-installer.com" ascii wide
		$ = "downloadzone.org" ascii wide

	condition:
		any of them
}