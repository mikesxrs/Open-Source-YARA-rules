rule apt_ext4_linuxlistener
{
 meta:
 description = "Detects Unique Linux Backdoor, Ext4"
 author = "Insikt Group, Recorded Future"
 TLP = "White"
 date = "2018-08-14"
 md5_x64 = "d08de00e7168a441052672219e717957"
 author = "https://go.recordedfuture.com/hubfs/reports/cta-2018-0816.pdf"
 strings:
 $s1="rm /tmp/0baaf161db39"
 $op1= {3c 61 0f}
 $op2= {3c 6e 0f}
 $op3= {3c 74 0f}
 $op4= {3c 69 0f}
 $op5= {3c 3a 0f}
 condition:
 all of them
}
