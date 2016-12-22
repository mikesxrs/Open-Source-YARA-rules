import "pe"

rule Elise_lstudio_variant_B_resource

{

meta:

description = "Elise lightserver variant."

author = "PwC Cyber Threat Operations :: @michael_yip"

version = "1.0"

created = "2015-12-16"

exemplar_md5 = "c205fc5ab1c722bbe66a4cb6aff41190"

 reference = "http://pwc.blogs.com/cyber_security_updates/2015/12/elise-security-through-obesity.html"

condition:

uint16(0) == 0x5A4D and for any i in (0..pe.number_of_resources - 1) : (pe.resources[i].type_string == "A\x00S\x00D\x00A\x00S\x00D\x00A\x00S\x00D\x00A\x00S\x00D\x00S\x00A\x00D\x00")

}
