rule neuron_common_strings {
 meta:
  description = "Rule for detection of Neuron based on commonly used strings"
  author = "NCSC UK"
  reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
  reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
  hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
 strings:
   $strServiceName = "MSExchangeService" ascii
   $strReqParameter_1 = "cadataKey" wide
   $strReqParameter_2 = "cid" wide
   $strReqParameter_3 = "cadata" wide
   $strReqParameter_4 = "cadataSig" wide
   $strEmbeddedKey = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnZ3WXRKcnNRZjVTcCtWVG9Rb2xuaEVkMHVwWDFrVElFTUNTNEFnRkRCclNmclpKS0owN3BYYjh2b2FxdUtseXF2RzBJcHV0YXhDMVRYazRoeFNrdEpzbHljU3RFaHBUc1l4OVBEcURabVVZVklVbHlwSFN1K3ljWUJWVFdubTZmN0JTNW1pYnM0UWhMZElRbnl1ajFMQyt6TUhwZ0xmdEc2b1d5b0hyd1ZNaz08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+" wide
   $strDefaultKey = "8d963325-01b8-4671-8e82-d0904275ab06" wide
   $strIdentifier = "MSXEWS" wide
   $strListenEndpoint = "443/ews/exchange/" wide
   $strB64RegKeySubstring = "U09GVFdBUkVcTWljcm9zb2Z0XENyeXB0b2dyYXBo" wide
   $strName = "neuron_service" ascii
   $dotnetMagic = "BSJB" ascii
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 6 of ($str*)
} 

rule neuron_standalone_signature {
 meta:
   description = "Rule for detection of Neuron based on a standalone signature from .NET metadata"
   author = "NCSC UK"
   reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
   reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
   hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
 strings:
   $a = {eb073d151231011234080e12818d1d051281311d1281211d1281211d128121081d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281}
   $dotnetMagic = "BSJB" ascii
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
} 

rule neuron_functions_classes_and_vars {
 meta:
   description = "Rule for detection of Neuron based on .NET function, variable and class names"
   author = "NCSC UK"
   reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
   reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
   hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
 strings:
   $class1 = "StorageUtils" ascii
   $class2 = "WebServer" ascii
   $class3 = "StorageFile" ascii
   $class4 = "StorageScript" ascii
   $class5 = "ServerConfig" ascii
   $class6 = "CommandScript" ascii
   $class7 = "MSExchangeService" ascii
   $class8 = "W3WPDIAG" ascii
   $func1 = "AddConfigAsString" ascii
   $func2 = "DelConfigAsString" ascii
   $func3 = "GetConfigAsString" ascii
   $func4 = "EncryptScript" ascii
   $func5 = "ExecCMD" ascii
   $func6 = "KillOldThread" ascii
   $func7 = "FindSPath" ascii
   $var1 = "CommandTimeWait" ascii
   $dotnetMagic = "BSJB" ascii
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 6 of them
}

rule nautilus_modified_rc4_loop {
 meta:
   description = "Rule for detection of Nautilus based on assembly code for a modified RC4 loop"
   author = "NCSC UK"
   reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
   reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
   hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
 strings:
   $a = {42 0F B6 14 04 41 FF C0 03 D7 0F B6 CA 8A 14 0C 43 32 14 13 41 88 12 49 FF C2 49 FF C9}
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $a
}

rule nautilus_rc4_key {
 meta:
   description = "Rule for detection of Nautilus based on a hardcoded RC4 key"
   author = "NCSC UK"
   reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
   reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
   hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
 strings:
   $key = {31 42 31 34 34 30 44 39 30 46 43 39 42 43 42 34 36 41 39 41 43 39 36 34 33 38 46 45 45 41 38 42}
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $key
}

rule nautilus_common_strings {
 meta:
   description = "Rule for detection of Nautilus based on common plaintext strings"
   author = "NCSC UK"
   reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
   reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
   hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
 strings:
   $ = "nautilus-service.dll" ascii
   $ = "oxygen.dll" ascii
   $ = "config_listen.system" ascii
   $ = "ctx.system" ascii
   $ = "3FDA3998-BEF5-426D-82D8-1A71F29ADDC3" ascii
   $ = "C:\\ProgramData\\Microsoft\\Windows\\Caches\\{%s}.2.ver0x0000000000000001.db" ascii
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and 3 of them
} 

rule nautilus_common_strings {
 meta:
  description = "Rule for detection of Nautilus based on common plaintext strings"
  author = "NCSC UK"
  reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
  reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
  hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
 strings:
  $ = "nautilus-service.dll" ascii
  $ = "oxygen.dll" ascii
  $ = "config_listen.system" ascii
  $ = "ctx.system" ascii
  $ = "3FDA3998-BEF5-426D-82D8-1A71F29ADDC3" ascii
  $ = "C:\\ProgramData\\Microsoft\\Windows\\Caches\\{%s}.2.ver0x0000000000000001.db" ascii
 condition:
  (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and 3 of them
} 

rule neuron2_loader_strings {
 meta:
  description = "Rule for detection of Neuron2 based on strings within the loader"
  author = "NCSC"
  reference = "https://www.ncsc.gov.uk/file/2768/download?token=An2Ro6YZ"
  reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
  hash = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"
 strings:
  $ = "dcom_api" ascii
  $ = "http://*:80/OWA/OAB/" ascii
  $ = "https://*:443/OWA/OAB/" ascii
  $ = "dcomnetsrv.cpp" wide
  $ = "dcomnet.dll" ascii
  $ = "D:\\Develop\\sps\\neuron2\\x64\\Release\\dcomnet.pdb" ascii
 condition:
  (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and 2 of them
}

rule neuron2_decryption_routine {
 meta:
  description = "Rule for detection of Neuron2 based on the routine used to decrypt the payload"
  author = "NCSC"
  reference = "https://www.ncsc.gov.uk/file/2768/download?token=An2Ro6YZ"
  reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
  hash = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"
 strings:
  $ = {81 FA FF 00 00 00 0F B6 C2 0F 46 C2 0F B6 0C 04 48 03 CF 0F B6 D1 8A 0C 14 8D 50 01 43 32 0C 13 41 88 0A 49 FF C2 49 83 E9 01}
 condition:
  (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}

rule neuron2_dotnet_strings {
 meta:
  description = "Rule for detection of the .NET payload for Neuron2 based on strings used"
  author = "NCSC"
  reference = "https://www.ncsc.gov.uk/file/2768/download?token=An2Ro6YZ"
  reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
  hash = "83d8922e7a8212f1a2a9015973e668d7999b90e7000c31f57be83803747df015"
 strings:
  $dotnetMagic = "BSJB" ascii
  $s1 = "http://*:80/W3SVC/" wide
  $s2 = "https://*:443/W3SVC/" wide
  $s3 = "neuron2.exe" ascii
  $s4 = "D:\\Develop\\sps\\neuron2\\neuron2\\obj\\Release\\neuron2.pdb" ascii
 condition:
  (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 2 of ($s*)
}
