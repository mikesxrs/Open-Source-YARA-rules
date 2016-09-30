rule eleonore_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "2f5ace22e886972a8dccc6aa5deb1e79"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var dfshk "
	$string1 = "arrow_next_down"
	$string2 = "return eval('yiyr.replac'"
	$string3 = "arrow_next_over"
	$string4 = "arrow_prev_over"
	$string5 = "xcCSSWeekdayBlock"
	$string6 = "xcCSSHeadBlock"
	$string7 = "xcCSSDaySpecial"
	$string8 = "xcCSSDay"
	$string9 = " window[df "
	$string10 = "day_special"
	$string11 = "var df"
	$string12 = "function jklsdjfk() {"
	$string13 = " sdjd "
	$string14 = "'e(/kljf hdfk sdf/g,fjkhd);');"
	$string15 = "arrow_next"
condition:
	15 of them
}
