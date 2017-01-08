/*
author: ben actis
notes: rough attempt to find more samples on vt via vt hunting.
       * special thanks to https://twitter.com/iMokhles/status/769362814490279936 
       * for reversing and posting screesnshot on twitter while i was on vaction without ios device

       * lookout i love you guys, please share hashes :)

       * jcase has awesome bbq

*/
rule iOSPegasusDetected
{
    strings:
        $a01 = "/private/var/root/test.app/data"
        $a02 = "/private/var/root/test.app/d/"
        $a03 = "/private/var/root/test.app"
        $a04 = "/private/var/tmp/crw"
        $a05 = "/private/var/tmp/cr"
        $a06 = "/private/var/tmp/st_data/"

    condition:
        any of them
}
