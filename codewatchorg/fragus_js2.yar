rule fragus_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f234c11b5da9a782cb1e554f520a66cf"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "(ELI6Q3PZ"
	$string1 = "SnJTbVJqV2tOa09VbGZSMHcwY0ZWZmRrRjBjRFY0Y3psVmNGVjROWGhBV0RZNGJWZzBVa1J4TjNCVlgwVmlhRjkyZURaS1NWOUhj"
	$string2 = "eFgweDNaek5YZDFkaWFtTlhZbDlmV2tGa09Va3pSMlEyT0dwSFFIQlZRblpEYzBKRWNFeGZOVmx6V0RSU1JEYzJjRlY0TVY5SFkw"
	$string3 = "VUpKUVdWS05ISlZjMXBTTUdWRlNFQmpaMjlrVDBCTFYzY3pZbGRpZG5oeldFUndkSE16YjB4M2JXSnFZMWRpZVY4ellreDNaMko1"
	$string4 = "((Yuii37DWU"
	$string5 = "YURVNFZXUlhjRlZDZGxsQVJ6UlNaRTlBUzFkM00ySlhiekU0ZEhnMWNrUjZZM0kyWDNaQmJGZ3hNMGxrTmpoVGVqRlpkSEUyV1dW"
	$string6 = "String.fromCharCode(ZZeD3LjJQ);}else if(QIyZsvvbEmVOpp"
	$string7 = "1);ELI6Q3PZ"
	$string8 = "));Yuii37DWU"
	$string9 = ");CUer0x"
	$string10 = "T1ZaQ05IUkRTVGhqT1VWd1ZWOUpRMlZLZG5oNlQwQkxWM2N6WWxkQmRrRkFPVmR3VlRsYWJsWnNOWGhKT1ZkeFZWazFRbEU1UlZK"
	$string11 = "TlpkM2wxS3lzcExUUTRYU2s4UEhocFVqRk9jazA3SUdsbUtIaHBVakZPY2swcGV5QkdWek5NVnlzOVVrSklWVE0wVDJ0NlpTZzJP"
	$string12 = "String.fromCharCode(((eMImGB"
	$string13 = "RGRDUkV0WFV6VkJkRkV4WHpCalYwRkhhRFk0YW5wamNqWmZka0ZzV0RaSWExZzBXWEZDUlZsQVpEWkJOMEoyZUhwd1duSlRXVE5J"
	$string14 = "SCpMaWXOuME(mi1mm8bu87rL0W);eval(Pcii3iVk1AG);</script></body></html>"
	$string15 = "Yuii37DWU"
	$string16 = "Yuii37DWU<<12"
	$string17 = "eTVzWlc1bmRHZ3NJRWhWUnpWRlJuRkZSRVUwUFRFd01qUXNJR2hQVlZsRVJFVmxVaXdnZUVKU1FscE1ORzF3Y21SMGJpd2dSbGN6"
condition:
	17 of them
}
