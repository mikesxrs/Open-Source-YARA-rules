rule zeroaccess_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "5f13fdfb53a3e60e93d7d1d7bbecff4f"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "document.createDocumentFragment();img.src"
	$string1 = "typeOf(events)"
	$string2 = "var i,x,y,ARRcookies"
	$string3 = "callbacks.length;j<l;j"
	$string4 = "encodeURIComponent(value);if(options.domain)value"
	$string5 = "event,HG.components.get('windowEvent_'"
	$string6 = "'read'in Cookie){return Cookie.read(c_name);}"
	$string7 = "item;},get:function(name,def){return HG.components.exists(name)"
	$string8 = "){window.addEvent(windowEvents[i],function(){var callbacks"
	$string9 = "reunload:function(callback){HG.events.add('beforeunload',callback);},add:function(event,callback){HG"
	$string10 = "name){if(HG.components.exists(name)){delete HG.componentList[name];}}},util:{uuid:function(){return'"
	$string11 = "window.HG"
	$string12 = "x.replace(/"
	$string13 = "encodeURIComponent(this.attr[key]));}"
	$string14 = "options.domain;if(options.path)value"
	$string15 = "this.page_sid;this.attr.user_sid"
condition:
	15 of them
}
