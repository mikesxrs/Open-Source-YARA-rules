rule cherryPicker
{
    meta:
        author = "Trustwave SpiderLabs"
        date = "2015-11-17"
        description = "Used to detect Cherry Picker malware.  Blog: https://www.trustwave.com/Resources/SpiderLabs-Blog/Shining-the-Spotlight-on-Cherry-Picker-PoS-Malware/?page=1&year=0&month=0"
    strings:
        $string1 = "srch1mutex" nocase
        $string2 = "SYNC32TOOLBOX" nocase
        $string3 = "kb852310.dll"
        $config1 = "[config]" nocase
        $config2 = "timeout"
        $config3 = "r_cnt"
        $config4 = "f_passive"
        $config5 = "prlog"
    condition:
        any of ($string*) or all of ($config*)

}

rule cherryInstaller
{
    strings:
        $string1 = "(inject base: %08x)"
        $string2 = "injected ok"
        $string3 = "inject failed"
        $string4 = "-i name.dll - install path dll"
        $string5 = "-s name.dll procname|PID - inject dll into processes or PID"
        $fileinfect1 = "\\ServicePackFiles\\i386\\user32.dll"
        $fileinfect2 = "\\dllcache\\user32.dll"
        $fileinfect3 = "\\user32.tmp"

    condition:
        all of ($string*) or all of ($fileinfect*)
}
