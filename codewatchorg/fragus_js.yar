rule fragus_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f234c11b5da9a782cb1e554f520a66cf"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "));ELI6Q3PZ"
	$string1 = "VGhNU2pWQmMyUXhPSFI2TTNCVGVEUXpSR3huYm1aeE5UaFhXRFI0ZFhCQVMxWkRNVGh0V0hZNFZVYzBXWFJpTVRoVFpFUklaVGxG"
	$string2 = "eFgweDNaek5YZDFkaWFtTlhZbDlmV2tGa09Va3pSMlEyT0dwSFFIQlZRblpEYzBKRWNFeGZOVmx6V0RSU1JEYzJjRlY0TVY5SFkw"
	$string3 = "TkhXa0ZrT1haNGRFSXhRM3BrTkRoVGMxZEJSMmcyT0dwNlkzSTJYM1pCYkZnMVVqQmpWMEZIYURZNGFucGpjalpmZGtGc1dERXpT"
	$string4 = "byKZKkpZU<<18"
	$string5 = ");CUer0x"
	$string6 = "bzWRebpU3yE>>16"
	$string7 = "RUJEWlVvMGNsVTVNMEpNWDNaNGJVSkpPRUJrUlVwRVQwQlNaR2cyY0ZWSE5GbDBRVFZ5UjFnMk9HVldOWGhMYUdFelRIZG5NMWQz"
	$string8 = "WnZSVGxuT1ZSRkwwaFZSelZGUm5GRlJFVTBLVHQ0UWxKQ1drdzBiWEJ5WkhSdVBtdG9XVWd6TVVGSGFFeDVTMlk3ZUVKU1FscE1O"
	$string9 = "QmZjMGN4YjBCd1oyOXBURUJJZEhvMFdYcGtOamhFV1ZwU01GVlZZbXBpUUZKV1lqTXpWMDAwY0dSNlF6aE1SekZ5ZEc4ME9FeEtN"
	$string10 = "SCpMaWXOuME("
	$string11 = "VjJKcVkxZGlYMTlhUVdRNVNUTkhaRFk0YWpsYWJsWkRNVGh0V0hZNFZVYzBXWFJ2Tm5CVmFEUlpWVmhDT0ZWV05YaDBRa1ZTUkUw"
	$string12 = "2;}else{Yuii37DWU"
	$string13 = "ELI6Q3PZ"
	$string14 = "ZUhNNVZYQlZlRFY0UUZnMk9HMVlORkpFYkRsNGMxbEpPRUJSTVY5SGNETllPRXB0YjBsaloySnhPVVZ3UkZWQVgzTllORGgwV0RS"
	$string15 = "S05GbE1lalk0Vm1ORmVEWnpXbEpXZDBWaU5ubzJjRlkzVjFsbFgwVmlURlpuYnpCUE5HNTBhRFpaVEZrMVFYTjZObkIwWTBVNE4x"
	$string16 = "Vm5CWFFVZG9OamhxZW1OeU5sOTJRV3hZTVROSlpEWTRVM294V1VSUFFFdFdZalE0WlVjeGNsSmtObmhBYURVNFZVZEFjRlZDZGtO"
	$string17 = "Yuii37DWU<<12"
	$string18 = ";while(hdnR9eo3pZ6E3<ZZeD3LjJQ.length){eMImGB"
condition:
	18 of them
}
