import “pe”

rule generic_carbon
{
 meta:
  author = "ESET Research"
  date = "2017-03-30"
  description = "Turla Carbon malware"
  reference = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
strings:
  $s1 = “ModStart”
  $s2 = “ModuleStart”
  $t1 = “STOP|OK”
  $t2 = “STOP|KILL”
condition:
  (uint16(0) == 0x5a4d) and (1 of ($s*)) and (1 of ($t*))
}

rule carbon_metadata
{
 meta:
  author = "ESET Research"
  date = "2017-03-30"
  description = "Turla Carbon malware"
  reference = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
condition:
  (pe.version_info[“InternalName”] contains “SERVICE.EXE” or pe.version_info[“InternalName”] contains “MSIMGHLP.DLL” or pe.version_info[“InternalName”] contains “MSXIML.DLL”) and pe.version_info[“CompanyName”] contains “Microsoft Corporation”
}
