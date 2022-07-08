rule apt_nazar_svchost_commands
{
    meta:
        description = "Detect Nazar's svchost based on supported commands"
        author = "Itay Cohen"
        date = "2020-04-26"
        reference = "<https://www.epicturla.com/blog/the-lost-nazar>"
        reference2 = "https://research.checkpoint.com/2020/nazar-spirits-of-the-past/"
        hash = "2fe9b76496a9480273357b6d35c012809bfa3ae8976813a7f5f4959402e3fbb6"
        hash = "be624acab7dfe6282bbb32b41b10a98b6189ab3a8d9520e7447214a7e5c27728"
    strings:
        $str1 = { 33 31 34 00 36 36 36 00 33 31 33 00 }
        $str2 = { 33 31 32 00 33 31 35 00 35 35 35 00 }
        $str3 = { 39 39 39 00 35 39 39 00 34 39 39 00 }
        $str4 = { 32 30 39 00 32 30 31 00 32 30 30 00 }
        $str5 = { 31 39 39 00 31 31 39 00 31 38 39 00 31 33 39 00 33 31 31 00 }
    condition:
        4 of them
}
