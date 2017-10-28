rule Java0daycve2012xxxx_generic
{
  meta:
     weight= "100"
     author = "Jaime Blasco"
     source = "alienvault"
     reference = "https://www.alienvault.com/blogs/labs-research/new-java-0day-exploited-in-the-wild"
     date = "2012-08"
  strings:
        $ = "java/security/ProtectionDomain"
        $ = "java/security/Permissions"
        $ = "java/security/cert/Certificate"
        $ = "setSecurityManager"
        $ = "file:///"
        $ = "sun.awt.SunToolkit"
        $ = "getField"
  condition:
    all of them
}
