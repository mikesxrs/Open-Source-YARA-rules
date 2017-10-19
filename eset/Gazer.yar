import “pe”
import “math”
import “hash”
rule Gazer_certificate_subject {
 meta:
 	author = "ESET"
  reference = "https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf"
 condition:
 for any i in (0..pe.number_of_signatures - 1):
 (pe.signatures[i].subject contains “Solid Loop” or
pe.signatures[i].subject contains “Ultimate Computer Support”)
}

rule Gazer_certificate
{
 meta:
 	author = "ESET"
  reference = "https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf"
 strings:
 	$certif1 = {52 76 a4 53 cd 70 9c 18 da 65 15 7e 5f 1f de 02}
 	$certif2 = {12 90 f2 41 d9 b2 80 af 77 fc da 12 c6 b4 96 9c}
 condition:
 (uint16(0) == 0x5a4d) and 1 of them and filesize < 2MB
}

rule Gazer_logfile_name
{
 meta:
 	author = "ESET"
  reference = "https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf"
 strings:
 	$s1 = “CVRG72B5.tmp.cvr”
 	$s2 = “CVRG1A6B.tmp.cvr”
 	$s3 = “CVRG38D9.tmp.cvr”
 condition:
 (uint16(0) == 0x5a4d) and 1 of them
}




