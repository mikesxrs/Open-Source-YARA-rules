rule PoS_Malware_ActiveComponent : FighterPOS
{
meta:
  description = "RAM scrapper component used by FighterPOS"
  author = "Trend Micro, Inc"
  reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/files/2016/02/fighterpos-gets-worm-routine-appendix.pdf"
strings:
  $pdb = /:\\users\\tom\\.{20,200}scan\.pdb/ nocase
condition:
  $pdb
}

rule PoS_Malware_MainBinary : FighterPOS
{
meta:
  description = "Main FighterPOS infector, with ActiveComponent asresource"
  author = "Trend Micro, Inc"
   reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/files/2016/02/fighterpos-gets-worm-routine-appendix.pdf"
strings:
  $string1 = "BrFighter"
  $string2 = "bot/dumper.php?id="
  $string3 = "bot/keylogger.php?id="
  $string4 = "\\Users\\avanni\\"
condition:
  (any of ($string*)) and PoS_Malware_ActiveComponent
}

rule PoS_Malware_MainBinary1 : FighterPOS
{
meta:
   description = "Main FighterPOS infector, without ActiveComponent as resource"
  author = "Trend Micro, Inc"
  reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/files/2016/02/fighterpos-gets-worm-routine-appendix.pdf"
strings:
  $string1 = "BrFighter"
   $string2 = "bot/dumper.php?id="
  $string3 = "bot/keylogger.php?id="
  $string4 = "\\Users\\avanni\\"
condition:
  (any of ($string*)) and not PoS_Malware_ActiveComponent
}

rule PoS_Malware_FlokiIntruder : FighterPOS
{
meta:
  description = "Main FighterPOS infector, with ActiveComponent as resource. FlokiIntruder release."
  author = "Trend Micro, Inc"
  reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/files/2016/02/fighterpos-gets-worm-routine-appendix.pdf"

strings:
  $string1 = "FlokiIntruder"
  $string2 = "bot/dumper.php" wide
  $string3 = "bot/key.php" wide
  $users1 = "\\Users\\UserPC\\" wide
  $users2 = "\\Users\\root\\" wide
condition:
  (all of ($string*)) and (any of ($users*)) and PoS_Malware_ActiveComponent
}

rule PoS_Malware_ TSPY_POSFIGHT.F: FighterPOS
{
meta:
  author = "Trend Micro, Inc"
  description = "FighterPOS modification, using TSPY_POSFIGHT.B OR TSPY_POSLOGR.SMY for scraping"
  reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/files/2016/02/fighterpos-gets-worm-routine-appendix.pdf"
strings:
  $string0 = "Software\\Borland\\Locales"
  $string1 = "SOFTWARE\\Borland\\Delphi\\RTL"
  $string2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  $string3 = "JavaWT"
  $string4 = "%s.Seek not implemented$Operation not allowed on sorted list" wide
  $string5 = "Toolhelp32ReadProcessMemory"
  $string6 = "VBWYT-BBWKV-P86YX-G642C-3C3D3"
  $string7 = "svchost.exe"
condition:
  all of them
}

rule PoS_Malware_EMVDataRecorder : FighterPOS
{
meta:
  description = "MSR 2006 EMV recorder by FighterPOS actor"
  author = "Trend Micro, Inc"
  reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/files/2016/02/fighterpos-gets-worm-routine-appendix.pdf"
strings:
  $a = "send_apdu -sc 0" wide
  $ = "C:\\GPShell\\data.dat" wide nocase
  $ = "MSVBVM60.DLL" ascii
  $ = "MSR 2006"
condition:
  #a > 10 and all of them
}
