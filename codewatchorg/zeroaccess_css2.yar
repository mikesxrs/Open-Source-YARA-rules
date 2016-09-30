rule zeroaccess_css2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "e300d6a36b9bfc3389f64021e78b1503"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "er div.panel-hide{display:block;position:absolute;z-index:200;margin-top:-1.5em;}div.panel-pane div."
	$string1 = "ve.gif) right center no-repeat;}div.ctools-ajaxing{float:left;width:18px;background:url(http://cdn3."
	$string2 = "cdn2.dailyrx.com"
	$string3 = "efefef;margin:5px 0 5px 0;}"
	$string4 = "node{margin:0;padding:0;}div.panel-pane div.feed a{float:right;}"
	$string5 = ":0 5px 0 0;float:left;}div.tweets-pulled-listing div.tweet-authorphoto img{max-height:40px;max-width"
	$string6 = "i a{color:"
	$string7 = ":bold;}div.tweets-pulled-listing .tweet-time a{color:silver;}div.tweets-pulled-listing  div.tweet-di"
	$string8 = "div.panel-pane div.admin-links{font-size:xx-small;margin-right:1em;}div.panel-pane div.admin-links l"
	$string9 = "div.tweets-pulled-listing ul{list-style:none;}div.tweets-pulled-listing div.tweet-authorphoto{margin"
	$string10 = "FFFFDD none repeat scroll 0 0;border:1px solid "
	$string11 = "vider{clear:left;border-bottom:1px solid "
condition:
	11 of them
}
