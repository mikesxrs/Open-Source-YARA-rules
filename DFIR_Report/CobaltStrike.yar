/*
https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
*/

import "pe"

rule CS_default_exe_beacon_stager {
meta:
description = "Remote CS beacon execution as a service - spoolsv.exe"
author = "TheDFIRReport"
date = "2021-07-13"
hash1 = "f3dfe25f02838a45eba8a683807f7d5790ccc32186d470a5959096d009cc78a2"
strings:
$s1 = "windir" fullword ascii
$s2 = "rundll32.exe" fullword ascii
$s3 = "VirtualQuery failed for %d bytes at address %p" fullword ascii
$s4 = "msvcrt.dll" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 800KB and (pe.imphash() == "93f7b1a7b8b61bde6ac74d26f1f52e8d" and
3 of them ) or ( all of them )
}

rule tdr615_exe { 
meta: 
description = "Cobalt Strike on beachhead: tdr615.exe" 
author = "TheDFIRReport" 
reference = "https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/" 
date = "2021-07-07" 
hash1 = "12761d7a186ff14dc55dd4f59c4e3582423928f74d8741e7ec9f761f44f369e5" 
strings: 
$a1 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
$a2 = "I:\\RoDcnyLYN\\k1GP\\ap0pivKfOF\\odudwtm30XMz\\UnWdqN\\01\\7aXg1kTkp.pdb" fullword ascii 
$b1 = "ealagi@aol.com0" fullword ascii 
$b2 = "operator co_await" fullword ascii 
$b3 = "GetModuleHandleRNtUnmapViewOfSe" fullword ascii 
$b4 = "RtlExitUserThrebNtFlushInstruct" fullword ascii 
$c1 = "Jersey City1" fullword ascii 
$c2 = "Mariborska cesta 971" fullword ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 10000KB and 
any of ($a* ) and 2 of ($b* ) and any of ($c* ) 
}
import "pe"

rule CS_DLL {
meta:
description = "62.dll"
author = "TheDFIRReport"
reference = "https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/"
date = "2021-07-07"
hash1 = "8b9d605b826258e07e63687d1cefb078008e1a9c48c34bc131d7781b142c84ab"
strings:
$s1 = "Common causes completion include incomplete download and damaged media" fullword ascii
$s2 = "StartW" fullword ascii
$s4 = ".rdata$zzzdbg" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 70KB and ( pe.imphash() == "42205b145650671fa4469a6321ccf8bf" )
or (all of them)
}

rule conti_cobaltstrike_192145_icju1_0 {
meta:
description = "files - from files 192145.dll, icju1.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "29bc338e63a62c24c301c04961084013816733dad446a29c20d4413c5c818af9"
hash2 = "e54f38d06a4f11e1b92bb7454e70c949d3e1a4db83894db1ab76e9d64146ee06"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s6 = "Velit consequuntur quisquam tempora error" fullword ascii
$s7 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s8 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s16 = "Dolorum eum ipsum tempora non et" fullword ascii
$s17 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
) or ( all of them )
}

rule cobalt_strike_tmp01925d3f {
meta:
description = "files - file ~tmp01925d3f.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "10ff83629d727df428af1f57c524e1eaddeefd608c5a317a5bfc13e2df87fb63"
strings:
$x1 = "C:\\Users\\hillary\\source\\repos\\gromyko\\Release\\gromyko.pdb" fullword ascii
$x2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
$s3 = "gromyko32.dll" fullword ascii
$s4 = "<requestedExecutionLevel level='asInvoker' uiAccess='false'/>" fullword ascii
$s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s6 = "https://sectigo.com/CPS0" fullword ascii
$s7 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
$s8 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
$s9 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
$s10 = "http://ocsp.sectigo.com0" fullword ascii
$s11 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
$s12 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
$s13 = "http://www.digicert.com/CPS0" fullword ascii
$s14 = "AppPolicyGetThreadInitializationType" fullword ascii
$s15 = "alerajner@aol.com0" fullword ascii
$s16 = "gromyko.inf" fullword ascii
$s17 = "operator<=>" fullword ascii
$s18 = "operator co_await" fullword ascii
$s19 = "gromyko" fullword ascii
$s20 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "1b1b73382580c4be6fa24e8297e1849d" or ( 1 of ($x*) or 4 of them ) )
}

rule cobalt_strike_TSE28DF {
meta:
description = "exe - file TSE28DF.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-05"
hash1 = "65282e01d57bbc75f24629be9de126f2033957bd8fe2f16ca2a12d9b30220b47"
strings:
$s1 = "mneploho86.dll" fullword ascii
$s2 = "C:\\projects\\Project1\\Project1.pdb" fullword ascii
$s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s4 = "AppPolicyGetThreadInitializationType" fullword ascii
$s5 = "boltostrashno.nfo" fullword ascii
$s6 = "operator<=>" fullword ascii
$s7 = "operator co_await" fullword ascii
$s8 = ".data$rs" fullword ascii
$s9 = "tutoyola" fullword ascii
$s10 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s11 = "vector too long" fullword ascii
$s12 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
$s13 = "network reset" fullword ascii /* Goodware String - occured 567 times */
$s14 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
$s15 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
$s16 = "network down" fullword ascii /* Goodware String - occured 567 times */
$s17 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */
$s18 = "connection aborted" fullword ascii /* Goodware String - occured 568 times */
$s19 = "network unreachable" fullword ascii /* Goodware String - occured 569 times */
$s20 = "host unreachable" fullword ascii /* Goodware String - occured 571 times */
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "ab74ed3f154e02cfafb900acffdabf9e" or all of them )
}

rule cobalt_strike_TSE588C {
meta:
description = "exe - file TSE588C.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-05"
hash1 = "32c13df5d411bf5a114e2021bbe9ffa5062ed1db91075a55fe4182b3728d62fe"
strings:
$s1 = "mneploho86.dll" fullword ascii
$s2 = "C:\\projects\\Project1\\Project1.pdb" fullword ascii
$s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s4 = "AppPolicyGetThreadInitializationType" fullword ascii
$s5 = "boltostrashno.nfo" fullword ascii
$s6 = "operator<=>" fullword ascii
$s7 = "operator co_await" fullword ascii
$s8 = "?7; ?<= <?= 6<" fullword ascii /* hex encoded string 'v' */
$s9 = ".data$rs" fullword ascii
$s10 = "tutoyola" fullword ascii
$s11 = "Ommk~z#K`majg`i4.itg~\".jkhbozk" fullword ascii
$s12 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s13 = "OVOVPWTOVOWOTF" fullword ascii
$s14 = "vector too long" fullword ascii
$s15 = "n>log2" fullword ascii
$s16 = "\\khk|k|4.fzz~4!!majk d" fullword ascii
$s17 = "network reset" fullword ascii /* Goodware String - occured 567 times */
$s18 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
$s19 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
$s20 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
condition:
uint16(0) == 0x5a4d and filesize < 900KB and
( pe.imphash() == "bb8169128c5096ea026d19888c139f1a" or 10 of them )
}

rule CS_encrypted_beacon_x86 {
meta:
author = "Etienne Maynier tek@randhome.io"
strings:
$s1 = { fc e8 ?? 00 00 00 }
$s2 = { 8b [1-3] 83 c? 04 [0-1] 8b [1-2] 31 }
condition:
$s1 at 0 and $s2 in (0..200) and filesize < 300000
}

rule CS_encrypted_beacon_x86_64 {
meta:
author = "Etienne Maynier tek@randhome.io"
strings:
$s1 = { fc 48 83 e4 f0 eb 33 5d 8b 45 00 48 83 c5 04 8b }
condition:
$s1 at 0 and filesize < 300000
}

rule CS_beacon {
meta:
author = "Etienne Maynier tek@randhome.io"

strings:
$s1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
$s2 = "%s as %s\\%s: %d" ascii
$s3 = "Started service %s on %s" ascii
$s4 = "beacon.dll" ascii
$s5 = "beacon.x64.dll" ascii
$s6 = "ReflectiveLoader" ascii
$s7 = { 2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f }
$s8 = { 69 68 69 68 69 6b ?? ?? 69 6b 69 68 }
$s9 = "%s (admin)" ascii
$s10 = "Updater.dll" ascii
$s11 = "LibTomMath" ascii
$s12 = "Content-Type: application/octet-stream" ascii

condition:
6 of them and filesize < 300000
}
