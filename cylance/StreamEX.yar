rule StreamEx
{
meta:
      author = "Cylance"
      description = "StreamEX shell crew"
      reference = "https://www.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      
strings:
      $a = "0r+8DQY97XGB5iZ4Vf3KsEt61HLoTOuIqJPp2AlncRCgSxUWyebhMdmzvFjNwka="
      $b = {34 ?? 88 04 11 48 63 C3 48 FF C1 48 3D D8 03 00 00}
      $bb = {81 86 ?? ?? 00 10 34 ?? 88 86 ?? ?? 00 10 46 81 FE D8 03 00 00}
      $c = "greendll"
      $d = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36" wide
      $f = {26 5E 25 24 23 91 91 91 91}
      $g = "D:\\pdb\\ht_d6.pdb"

condition:
      $a or $b or $bb or ($c and $d) or $f or $g
