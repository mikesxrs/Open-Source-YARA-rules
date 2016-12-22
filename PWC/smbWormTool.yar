rule smbWormTool

 {

 meta:

 author = "PwC Cyber Threat Operations"

 description = "SMB Worm Tool"

 version = "1.0"

 created = "2014-12-30"

 osint_ref =

 "http://totalhash.com/analysis/db6cae5734e433b195d8fc3252cbe58469e42bf3"

 exemplar_md5 = "61bf45be644e03bebd4fbf33c1c14be2"

 reference = "http://pwc.blogs.com/cyber_security_updates/2015/01/destructive-malware.html"

 strings:

 $STR1 = "%s\\Admin$\\%s.exe" wide ascii nocase

 $STR2 ="NetScheduleJobAdd" wide ascii nocase

 $STR3 = "SetServiceStatus failed, error code" wide   ascii nocase

 $STR4 = "LoadLibrary( NTDLL.DLL ) Error" wide ascii   nocase

 $STR5 = "NTLMSSP" wide ascii nocase

 condition:

 all of them

 }
