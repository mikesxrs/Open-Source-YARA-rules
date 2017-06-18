rule Ham_backdoor
{
meta:
  author = "Cylance Spear Team"
  reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
strings:
  $a = {8D 14 3E 8B 7D FC 8A 0C 11 32 0C 38 40 8B 7D 10 88 0A 8B 4D 08 3B C3}
  $b = {8D 0C 1F 8B 5D F8 8A 04 08 32 04 1E 46 8B 5D 10 88 01 8B 45 08 3B F2}
condition:
  $a or $b
}

rule Tofu_Backdoor
{
meta:
  author = "Cylance Spear Team"
  reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
strings:
	$a = "Cookies: Sym1.0"
	$b = "\\\\.\\pipe\\1[12345678]"
	$c = {66 0F FC C1 0F 11 40 D0 0F 10 40 D0 66 0F EF C2 0F 11 40 D0 0F 10 40 E0}
condition:
	$a or $b or $c
}
