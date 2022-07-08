rule Mozi_Obfuscation_Technique
{
  meta:
    author =  "Elastic Security, Lars Wallenborn (@larsborn)"
    description = "Detects obfuscation technique used by Mozi botnet."
    reference = "https://www.elastic.co/security-labs/collecting-and-operationalizing-threat-data-from-the-mozi-botnet"
  strings:
    $a = { 55 50 58 21
           [4]
           00 00 00 00
           00 00 00 00
           00 00 00 00 }
  condition:
    all of them
}
