rule xll_custom_builder
{
  meta:
    description = "XLL Custom Builder"
    reference = "https://threatresearch.ext.hp.com/how-attackers-use-xll-malware-to-infect-systems/"
    author = "patrick.schlapfer@hp.com"
    date = "2022-01-07"

  strings:
    $str1 = "xlAutoOpen"
    $str2 = "test"
    $op1 = { 4D 6B C9 00 }
    $op2 = { 4D 31 0E }
    $op3 = { 49 83 C6 08 }
    $op4 = { 49 39 C6 }

  condition:
    uint16(0) == 0x5A4D and all of ($str*) and all of ($op*) and filesize < 10KB
}
