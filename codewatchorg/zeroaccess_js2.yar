rule zeroaccess_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "b5fda04856b98c254d33548cc1c1216c"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "ApiClientConfig"
	$string1 = "function/.test(pa.toString())"
	$string2 = "background-image:url(http:\\/\\/static.ak.fbcdn.net\\/rsrc.php\\/v2\\/y6\\/x\\/s816eWC-2sl.gif)}"
	$string3 = "Music.init"
	$string4 = "',header:'bool',recommendations:'bool',site:'hostname'},create_event_button:{},degrees:{href:'url'},"
	$string5 = "cca6477272fc5cb805f85a84f20fca1d"
	$string6 = "document.createElement('form');c.action"
	$string7 = "javascript:false"
	$string8 = "s.onMessage){j.error('An instance without whenReady or onMessage makes no sense');throw new Error('A"
	$string9 = "NaN;}else h"
	$string10 = "sprintf"
	$string11 = "window,j"
	$string12 = "o.getUserID(),da"
	$string13 = "FB.Runtime.getLoginStatus();if(b"
	$string14 = ")');k.toString"
	$string15 = "rovide('XFBML.Send',{Dimensions:{width:80,height:25}});"
	$string16 = "{log:i};e.exports"
	$string17 = "a;FB.api('/fql','GET',f,function(g){if(g.error){ES5(ES5('Object','keys',false,b),'forEach',true,func"
	$string18 = "true;}}var ia"
condition:
	18 of them
}
