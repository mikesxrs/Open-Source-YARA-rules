 rule MSSUP : AST

{

meta:

       author="PwC Cyber Threat Operations"

       date="2014-09-11"

       hash="8083ee212588a05d72561eebe83c57bb"
       
       reference = "http://pwc.blogs.com/cyber_security_updates/2014/09/malware-microevolution.html"

 strings:

       $debug1="d:\\Programming\\CSharp\\BlackBerry\\BlackBerry\\obj\\Debug\\MSSUP.pdb" nocase

       $debug2="D:\\Programming\\CSharp\\BlackBerry\\UploadDownload\\bin\\x86\\Debug\\UploadDownload.pdb" nocase

       $debug3="Unexpected error has been occurred in {0}, the process must restart for some reason, if it's first time you see this message restart the {0}, if problem was standing contacts the support team ."

       $fileheader1="MSSUP" ascii wide

       $fileheader2="1.0.0.0" ascii wide

       $fileheader3="2014" ascii wide

       $configload1="sqlite3.dll"

       $configload2="URLExtractRegex"

       $configload3="HTTPHeaderName"

       $configload4="HTTPHeaderType"

       $configload5="MsupPath"

 

condition:

       (all of ($fileheader*) or 3 of ($configload*)) and filesize < 200KB or any of ($debug*)

}

