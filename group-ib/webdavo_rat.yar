import "pe"

rule webdavo_rat
{
  meta:
    author = "Dmitry Kupin"
    company = "Group-IB"
    family = "webdavo.rat"
    description = "Suspected Webdav-O RAT (YaDisk)"
    reference = "https://blog.group-ib.com/task"
    sample = "7874c9ab2828bc3bf920e8cdee027e745ff059237c61b7276bbba5311147ebb6" // x86
    sample = "849e6ed87188de6dc9f2ef37e7c446806057677c6e05a367abbd649784abdf77" // x64
    severity = 9
    date = "2021-06-10"

  strings:
    $rc4_key_0 = { 8A 4F 01 47 34 C9 75 F8 2B C8 C1 E9 D2 F3 A5 8B }
    $rc4_key_1 = { C3 02 03 04 05 DD EE 08 09 10 11 12 1F D2 15 16 }
    $s0 = "y_dll.dll" fullword ascii
    $s1 = "test3.txt" fullword ascii
    $s2 = "DELETE" fullword wide
    $s3 = "PROPFIND" fullword wide

  condition:
    (any of ($rc4_key*) or 3 of ($s*)) or
    (
     pe.imphash() == "43021febc8494d66a8bc60d0fa953473" or
     pe.imphash() == "68320a454321f215a3b6fcd7d585626b"
    )
}
