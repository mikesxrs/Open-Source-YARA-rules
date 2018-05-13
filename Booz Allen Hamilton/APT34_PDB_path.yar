{
  meta:
    author = "Booz Allen Hamilton"
    reference = "https://www.boozallen.com/s/insight/blog/dark-labs-discovers-apt34-malware-variants.html"
    malware = "exerunner"
    actor = "APT34"
  strings:
    $exeruner_string_1 = "C:\\Users\\aaa\\documents\\visual studio 2015\\Projects\\exeruner\\exeruner\\obj\\Debug\\exeruner.pdb"
    $exeruner_string_2 = "C:\\Users\\aaa\\Desktop\\test\\exeruner\\exeruner\\obj\\Debug\\exeruner_new.pdb"

  condition:
    $exeruner_string_1 or $exeruner_string_2
}
