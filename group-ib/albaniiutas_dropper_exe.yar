import "pe"

rule albaniiutas_dropper_exe
{
  meta:
    author = "Dmitry Kupin"
    company = "Group-IB"
    family = "albaniiutas.dropper"
    description = "Suspected Albaniiutas dropper"
    reference = "https://blog.group-ib.com/task"
    sample = "2a3c8dabdee7393094d72ce26ccbce34bff924a1be801f745d184a33119eeda4" // csrss.exe dropped from 83b619f65...
    sample = "71750c58eee35107db1a8e4d583f3b1a918dbffbd42a6c870b100a98fd0342e0" // csrss.exe dropped from 690bf6b83...
    sample = "83b619f65d49afbb76c849c3f5315dbcb4d2c7f4ddf89ac93c26977e85105f32" // dropper_stage_0 with decoy
    sample = "690bf6b83cecbf0ac5c5f4939a9283f194b1a8815a62531a000f3020fee2ec42" // dropper_stage_0 with decoy
    severity = 9
    date = "2021-07-06"

  strings:
    $eventname = /[0-9A-F]{8}-[0-9A-F]{4}-4551-8F84-08E738AEC[0-9A-F]{3}/ fullword ascii wide
    $rc4_key = { 00 4C 21 51 40 57 23 45 24 52 25 54 5E 59 26 55 2A 41 7C 7D 74 7E 6B 00 } // L!Q@W#E$R%T^Y&U*A|}t~k
    $aes256_str_seed = { 00 65 34 65 35 32 37 36 63 30 30 30 30 31 66 66 35 00 } // e4e5276c00001ff5
    $s0 = "Release Entery Error" fullword ascii
    $s1 = "FileVJCr error" fullword ascii
    $s2 = "wchWSMhostr error" fullword ascii
    $s3 = "zlib err0r" fullword ascii
    $s4 = "De err0r" fullword ascii
    $s5 = "CreateFileW_CH error!" fullword ascii
    $s6 = "GetConfigOffset error!" fullword ascii

  condition:
    5 of them or
    (
     pe.imphash() == "222e118fa8c0eafeef102e49953507b9" or
     pe.imphash() == "7210d5941678578c0a31adb5c361254d" or
     pe.imphash() == "41e9907a6c468b4118e968a01461a45b"
    )
}
