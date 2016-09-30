rule zeroaccess_css
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "4944324bad3b020618444ee131dce3d0"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "close-mail{right:130px "
	$string1 = "ccc;box-shadow:0 0 5px 1px "
	$string2 = "757575;border-bottom:1px solid "
	$string3 = "777;height:1.8em;line-height:1.9em;display:block;float:left;padding:1px 15px;margin:0;text-shadow:-1"
	$string4 = "C4C4C4;}"
	$string5 = "999;-webkit-box-shadow:0 0 3px "
	$string6 = "header div.service-links ul{display:inline;margin:10px 0 0;}"
	$string7 = "t div h2.title{padding:0;margin:0;}.box5-condition-news h2.pane-title{display:block;margin:0 0 9px;p"
	$string8 = "footer div.comp-info p{color:"
	$string9 = "pcmi-listing-center .full-page-listing{width:490px;}"
	$string10 = "pcmi-content-top .photo img,"
	$string11 = "333;}div.tfw-header a var{display:inline-block;margin:0;line-height:20px;height:20px;width:120px;bac"
	$string12 = "ay:none;text-decoration:none;outline:none;padding:4px;text-align:center;font-size:9px;color:"
	$string13 = "333;}body.page-videoplayer div"
	$string14 = "373737;position:relative;}body.node-type-video div"
	$string15 = "pcmi-content-sidebara,.page-error-page "
	$string16 = "fff;text-decoration:none;}"
	$string17 = "qtabs-list li a,"
	$string18 = "cdn2.dailyrx.com"
condition:
	18 of them
}
