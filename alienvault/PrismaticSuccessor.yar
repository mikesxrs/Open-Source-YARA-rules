rule PrismaticSuccessor : LinuxMalware

{

   meta:

       author = "AlienLabs"

       description = "Prismatic Successor malware backdoor"

       reference = "aaeee0e6f7623f0087144e6e318441352fef4000e7a8dd84b74907742c244ff5"
       
       reference2 = "https://cybersecurity.att.com/blogs/labs-research/prism-attacks-fly-under-the-radar

       copyright = "Alienvault Inc. 2021"


   strings:

       $s1 = "echo -e \""

       $s2 = "[\x1B[32m+\x1B[0m]`/bin/hostname`"

       $s3 = "[\x1B[32m+\x1B[0m]`/usr/bin/id`"

       $s4 = "[\x1B[32m+\x1B[0m]`uname -r`"

       $s5 = "[+]HostUrl->\t%s\n"

       $s6 = "[+]PortUrl->\t%s\n"

       $s7 = "/var/run/sshd.lock"


       $shellcode = {

           48 31 C9

           48 81 E9 [4]

           48 8D 05 [4]

           48 BB [8]

           48 31 [2]

           48 2D [2-4]

           E2 F4

       }


       $c1 = {

           8B 45 ??

           BE 00 00 00 00

           89 C7

           E8 [4]

           8B 45 ??

           BE 01 00 00 00

           89 C7

           E8 [4]

           8B 45 ??

           BE 02 00 00 00

           89 C7

           E8 [4]

           8B 45 ??

           BA [4]

           BE [4]

           89 C7

           E8

       }


   condition:

       uint32(0) == 0x464C457F and

       filesize > 500KB and filesize < 5MB and

       5 of ($s*) and

       all of ($c*) and

       #shellcode == 2

}
