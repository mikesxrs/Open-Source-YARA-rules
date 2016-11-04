rule CrowdStrike_CSIT_14004_02 : loader backdoor bouncer  {
meta:
    description = "Deep Panda Compiled ASP.NET <http://ASP.NET> Webshell"
    last_modified = "2014-04-25"
    version = "1.0"
    report = "CSIT-14004"
    in_the_wild = true
    copyright = "CrowdStrike, Inc"
    actor = "DEEP PANDA"
   strings:
    $cookie = "zWiz\x00" wide
    $cp = "es-DN" wide
    $enum_fs1 = "File system: {0}" wide
    $enum_fs2 = "Available: {0} bytes" wide
    $enum_fs3 = "Total space: {0} bytes" wide
    $enum_fs4 = "Total size: {0} bytes" wide
   condition:
    ($cookie and $cp) or all of ($enum*)
}