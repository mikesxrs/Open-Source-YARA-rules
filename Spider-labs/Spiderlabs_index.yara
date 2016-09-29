/*

  Copyright
  =========
  Copyright (C) 2013 Trustwave Holdings, Inc.
 
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>

  ---------

  This YARA signature will attempt to detect instances of the newly discovered
  Apache iFrame injection module. Please take a minute to look at the references
  contained in the metadata section of the rule for further information.

  This signature attempts to identify the unique XTEA function used for config
  decryption. Additionally, it will attempt to identify the XTEA keys discovered
  in the samples already encountered by SpiderLabs.

*/


rule apacheInjectionXtea {
  meta:
    description = "Detection for new Apache injection module spotted in wild."
    in_the_wild = true
    reference1 = "http://blog.sucuri.net/2013/06/new-apache-module-injection.html"
    reference2 = "TBD"

  strings:
    $xteaFunction = { 8B 0F 8B 57 04 B8 F3 3A 62 CC 41 89 C0 41 89 C9 41 89 CA 41 C1 E8 0B 41 C1 E2 04 41 C1 E9 05 41 83 E0 03 45 31 D1 46 8B 04 86 41 01 C9 41 01 C0 05 47 86 C8 61 45 31 C8 44 29 C2 49 89 C0 41 83 E0 03 41 89 D1 41 89 D2 46 8B 04 86 41 C1 E9 05 41 C1 E2 04 45 31 D1 41 01 D1 41 01 C0 45 31 C8 44 29 C1 85 C0 75 A3 89 0F 89 57 04 C3 }
    $xteaKey1 = { 4A F5 5E 5E B9 8A E1 63 30 16 B6 15 23 51 66 03 }
    $xteaKey2 = { 68 2C 16 4A 30 A8 14 1F 1E AD 0D 24 E1 0E 10 01 }

  condition:
    $xteaFunction or any of ($xteaKey*)
}

rule cherryPicker
{
    meta:
        author = "Trustwave SpiderLabs"
        date = "2015-11-17"
        description = "Used to detect Cherry Picker malware.  Blog: https://www.trustwave.com/Resources/SpiderLabs-Blog/Shining-the-Spotlight-on-Cherry-Picker-PoS-Malware/?page=1&year=0&month=0"
    strings:
        $string1 = "srch1mutex" nocase
        $string2 = "SYNC32TOOLBOX" nocase
        $string3 = "kb852310.dll"
        $config1 = "[config]" nocase
        $config2 = "timeout"
        $config3 = "r_cnt"
        $config4 = "f_passive"
        $config5 = "prlog"
    condition:
        any of ($string*) or all of ($config*)

}

rule cherryInstaller
{
    strings:
        $string1 = "(inject base: %08x)"
        $string2 = "injected ok"
        $string3 = "inject failed"
        $string4 = "-i name.dll - install path dll"
        $string5 = "-s name.dll procname|PID - inject dll into processes or PID"
        $fileinfect1 = "\\ServicePackFiles\\i386\\user32.dll"
        $fileinfect2 = "\\dllcache\\user32.dll"
        $fileinfect3 = "\\user32.tmp"

    condition:
        all of ($string*) or all of ($fileinfect*)
}

rule Punkey
{
  meta:
    author = "Trustwave SpiderLabs"
    date = "2015-04-09"
    description = "Used to detect Punkey malware.  Blog: https://www.trustwave.com/Resources/SpiderLabs-Blog/New-POS-Malware-Emerges---Punkey/"
  strings:
    $pdb1 = "C:\\Documents and Settings\\Administrator\\Desktop\\Verios\\jusched\\jusched32.pdb" nocase
    $pdb2 = "C:\\Documents and Settings\\Administrator\\Desktop\\Verios\\jusched\\troi.pdb" nocase
    $pdb3 = "D:\\freelancer\\gale.kreeb\\jusched10-19\\jusched32.pdb" nocase
    $pdb4 = "D:\\freelancer\\gale.kreeb\\jusched10-19\\troi.pdb" nocase
    $pdb5 = "C:\\Users\\iptables\\Desktop\\x86\\jusched32.pdb" nocase
    $pdb6 = "C:\\Users\\iptables\\Desktop\\x86\\troi.pdb"
    $pdb7 = "C:\\Users\\iptables\\Desktop\\27 Octomber\\jusched10-27\\troi.pdb" nocase
    $pdb8 = "D:\\work\\visualstudio\\jusched\\dllx64.pdb" nocase
    $string0 = "explorer.exe" nocase
    $string1 = "jusched.exe" nocase
    $string2 = "dllx64.dll" nocase
    $string3 = "exportDataApi" nocase
    $memory1 = "troi.exe"
    $memory2 = "unkey="
    $memory3 = "key="
    $memory4 = "UPDATE"
    $memory5 = "RUN"
    $memory6 = "SCANNING"
    $memory7 = "86afc43868fea6abd40fbf6d5ed50905"
    $memory8 = "f4150d4a1ac5708c29e437749045a39a"

  condition:
    (any of ($pdb*)) or (all of ($str*)) or (all of ($mem*))
}
