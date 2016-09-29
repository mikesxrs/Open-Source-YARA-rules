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