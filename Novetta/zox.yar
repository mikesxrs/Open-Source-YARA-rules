rule zox
{
	meta:
		Author = "Novetta"
		Reference = "https://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf"

	strings:
		$url ="png&w=800&h=600&ei=CnJcUcSBL4rFkQX444HYCw&zoom=1&ved=1t:3588,r:1,s:0,i:92&iact=rc&dur=368&page=1&tbnh=184&tbnw=259&start=0&ndsp=20&tx=114&ty=58"

	condition:
		$url
}