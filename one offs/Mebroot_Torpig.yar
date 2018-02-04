rule Mebroot_Torpig
{
 meta:
  author = "perpetualhorizon"
  reference = "https://perpetualhorizon.blogspot.com/2010/05/trip-down-memory-lane-with-torpig-part.html"
 strings:
  $a = "[avorp1_251]" fullword
  $b = "Temp\\$$$dq3e" fullword
  $c = "Temp$67we.$" fullword
  $d = "Temp\\xsw2" fullword
  $e = "controlpanel r57shell.php c99shell" fullword
  $f = "66.135.61.80" fullword
  $g = "72.51.34.52" fullword

 condition:
  any of them
}
