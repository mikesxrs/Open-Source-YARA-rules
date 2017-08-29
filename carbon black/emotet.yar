rule Word_Emotet_Dropper_2017Aug : TAU Word Emotet VBA

{

meta:

author = "Carbon Black TAU"

date = "2017-August-22"

description = "Emotet Word Document Dropper utilizing embedded Comments and Custom Properties Fields"

reference = "https://www.carbonblack.com/2017/08/28/threat-analysis-word-documents-embedded-macros-leveraging-emotet-trojan/"

yara_version = "3.5.0"

exemplar_hashes = "20ca01986dd741cb475dd0312a424cebb53f1201067938269f2e746fb90d7c2e, c7cab605153ac4718af23d87c506e46b8f62ee2bc7e7a3e6140210c0aeb83d48, 3ca148e6d17868544170351c7e0dbef38e58de9435a2f33fe174c83ea9a5a7f5"

strings:

$signature = {D0 CF 11 E0}

$base = /JAB7\w{100,}={0,2}/

$s1 = "BuiltInDocumentProperties"

$s2 = "CustomDocumentProperties"

$s3 = "Run"

$s4 = "VBA"

$s6 = "Comments"

$s7 = "autoopen"

$s8 = "Module1"

$s9 = "Picture 1" wide

$s10 = "JFIF"

condition:

$signature at 0 and

$base in (0x8200..0x9000) and

8 of ($s*)

}

