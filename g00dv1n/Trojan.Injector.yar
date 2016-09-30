rule TrojanInjectorA
{
   meta:
       Description = "Trojan.Injector.vb"
       ThreatLevel = "5"

   strings:
		$ = "KERNEO32.nll"  ascii wide
		$ = "CfeateFileAaocwwA"  ascii wide
		$ = "RGPdFileREjhsoX"  ascii wide

   condition:
      all of them
}
