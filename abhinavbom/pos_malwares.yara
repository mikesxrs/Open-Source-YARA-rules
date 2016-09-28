rule FastPOS
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "06/10/2016"
  description = "rule to detect FastPOS Mutex"
  ref1 = "5aabd7876faba0885fccc8b4d095537bd048b6943aaacaf3e01d204450e787c6"

strings:
  $string1 = "uniqyeidclaxemain"
  $string2 = "http://%s/cdosys.php"
  
condition:        
  all of ($string*)
  
}