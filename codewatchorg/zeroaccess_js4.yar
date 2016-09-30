rule zeroaccess_js4
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "268ae96254e423e9d670ebe172d1a444"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ").join("
	$string1 = "JSON.stringify:function(o){if(o"
	$string2 = "){try{var a"
	$string3 = ");return $.jqotecache[i]"
	$string4 = "o.getUTCFullYear(),hours"
	$string5 = "seconds"
	$string6 = "')');};$.secureEvalJSON"
	$string7 = "isFinite(n);},secondsToTime:function(sec_numb){sec_numb"
	$string8 = "')');}else{throw new SyntaxError('Error parsing JSON, source is not valid.');}};$.quoteString"
	$string9 = "o[name];var ret"
	$string10 = "a[m].substr(2)"
	$string11 = ");if(d){return true;}}}catch(e){return false;}}"
	$string12 = "a.length;m<k;m"
	$string13 = "if(parentClasses.length"
	$string14 = "o.getUTCHours(),minutes"
	$string15 = "$.jqote(e,d,t),$$"
	$string16 = "q.test(x)){e"
	$string17 = "{};HGWidget.creator"
condition:
	17 of them
}
