rule AdwareDlhelperAdSample
{
	meta:
		Description  = "Adware.Dlhelper.vb"
		ThreatLevel  = "5"

	strings:

		$ = "trifonov@onegbsoft.ru" ascii wide
		$ = "bulovackiy@dontehnoservis.com.ua" ascii wide
		$ = "contacts@dayzgames.com" ascii wide
		$ = "admin@mayris.org" ascii wide

		$ = "Panel_OffersList" ascii wide

		$ = "support@dlhelper.com" ascii wide
		$ = "http://dlhelper.com" ascii wide

		$ = "http://sendme9.ru" ascii wide
		$ = "http://sendme3.ru" ascii wide
		$ = "http://trustfile3.ru" ascii wide
		$ = "http://trustfile9.ru" ascii wide
		$ = "http://downloaditeasy.ru" ascii wide

	condition:
		any of them
}