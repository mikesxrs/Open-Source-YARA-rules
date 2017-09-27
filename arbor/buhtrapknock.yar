rule buhtrapknock {

meta:

 author = "Curt Wilson"
 org    = "Arbor Networks ASERT"
 ref    = "https://www.arbornetworks.com/blog/asert/diving-buhtrap-banking-trojan-activity/"
 hash   = "a0c428ae70bfc7fff66845698fb8ce045bffb3114dde4ea2eac19561a619c6c8"
 desc   = "connects to C2 and issues HTTP client request for knock.html"

strings:

 $s1 = "C:\\Users\\dev\\Documents\\Visual Studio 2015\\Projects\\knock\\Release\\knock.pdb" ascii wide
 $s2 = "User-Agent: Mozilla/5.0 (compatible; MSIE 273.0; Windows NT 6.1; WOW64; Trident/5.0; MASP)" ascii wide
 $s3 = "/knock.html" ascii wide

condition:

uint16(0) == 0x5a4d and 2 of ($s*)
}
