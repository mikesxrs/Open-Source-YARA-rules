rule webshell_chinachopper_oab
 
{
 
meta:
 
author = "Jeff White (Palo Alto Networks) @noottrak"

reference = "https://unit42.paloaltonetworks.com/china-chopper-webshell/"
 
date = "02MAR2021"
 
hash01 = "e8ea17cd1de6d3389c792cce8c0ff1927a6386f0ef32ab0b097763de1f86ffc8"
 
hash02 = "34f9944a85ffba58f3fa60c5dc32da1ce6743dae261e1820ef6c419808757112"
 
hash03 = "55fbfab29f9d2c26f81f1ff901af838110d7f76acc81f14b791a8903aa8b8425"
 
hash04 = "6e75bbcdd22ec9df1c7796e381a83f88e3ae82f5698c6b31b64d8f11e9cfd867"
 
strings:
 
// Detect OAB file
 
$OAB01 = "ExternalUrl" ascii // Contains webshell
 
$OAB02 = "InternalUrl" ascii
 
$OAB03 = "ExchangeVersion" ascii
 
$OAB04 = "WhenChangedUTC" ascii
 
// Detect injected Url variants
 
$HTTP01 = "http://f/" ascii nocase
 
$HTTP02 = "http://g/" ascii nocase
 
$HTTP03 = "http://p/" ascii nocase
 
// Detect ChinaChopper variants
 
$websh01 = "<script language=\"JScript\"" ascii nocase
 
$websh02 = "<script language=\"c#\"" ascii nocase
 
$websh03 = "<script runat=\"server\"" ascii nocase
 
// Detect webshell anchors
 
$cc01 = "Request" ascii nocase
 
$cc02 = "Page_Load" ascii nocase
 
 
 
 
// Detect injected pattern, no webshell
 
$non = /http:\/\/[a-z]\/[a-z0-9]+/
 
condition:
 
(all of ($OAB*) and 1 of ($HTTP*) and 1 of ($websh*) and all of ($cc*))
 
or
 
(all of ($OAB*) and $non)
 
}
