rule BackdoorLiudoor
{
meta:
        author = "RSA FirstWatch"
        date = "2015-07-23"
        Description = "Backdoor.Liudoor.sm"
        ThreatLevel  = "5"
        hash0 = "78b56bc3edbee3a425c96738760ee406"
        hash1 = "5aa0510f6f1b0e48f0303b9a4bfc641e"
        hash2 = "531d30c8ee27d62e6fbe855299d0e7de"
        hash3 = "2be2ac65fd97ccc97027184f0310f2f3"
		hash4 = "6093505c7f7ec25b1934d3657649ef07"
        type = "Win32 DLL"

strings:
        $string0 = "Succ" ascii wide
        $string1 = "Fail" ascii wide
        $string2 = "pass" ascii wide
        $string3 = "exit" ascii wide
        $string4 = "svchostdllserver.dll" ascii wide
        $string5 = "L$,PQR" ascii wide
        $string6 = "0/0B0H0Q0W0k0" ascii wide
        $string7 = "QSUVWh" ascii wide
        $string8 = "Ht Hu[" ascii wide
condition:
        all of them
}
