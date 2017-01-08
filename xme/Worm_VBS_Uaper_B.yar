rule Worm_VBS_Uaper_B
{
meta:
    description = "Example rule from blog"
    author = "Xavier Mertens"
    reference = "https://blog.rootshell.be/2012/06/20/cuckoomx-automating-email-attachments-scanning-with-cuckoo/"
strings:
  $a0 = { 466f72204f353d3120546f204f332e41646472657373456e74726965732e436f756e74 }
  $a1 = { 536574204f363d4f332e41646472657373456e7472696573284f3529 }
  $a2 = { 4966204f353d31205468656e }
  $a3 = { 4f342e4243433d4f362e41646472657373 }
  $a4 = { 456c7365 }
  $a5 = { 4f342e4243433d4f342e424343202620223b20222026204f362e41646472657373 }

condition:
  $a0 and $a1 and $a2 and $a3 and $a4 and $a5
}
