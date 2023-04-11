rule Java0daycve2012xxxx_generic
{
  meta:
     weight=100
     author = "Jaime Blasco"
     source = "alienvault"
     date = "2012-08"
     report = "https://cybersecurity.att.com/blogs/labs-research/new-java-0day-exploited-in-the-wild"
  strings:
        $ =  "java/security/ProtectionDomain"
        $ = "java/security/Permissions"
        $ = "java/security/cert/Certificate"
        $ = "setSecurityManager"
        $ = "file:///"
        $ = "sun.awt.SunToolkit"
        $ = "getField"
  condition:
    all of them
}
