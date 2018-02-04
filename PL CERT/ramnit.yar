import "pe"

rule ramnit_general {

  meta:
    author = "nazywam"
    module = "ramnit"
    reference = "https://www.cert.pl/en/news/single/ramnit-in-depth-analysis/"

  strings:
    $guid = "{%08X-%04X-%04X-%04X-%08X%04X}"

    $md5_magic_1 = "15Bn99gT"
    $md5_magic_2 = "1E4hNy1O"

    $init_dga = { C7 ?? ?? ?? ?? ?? FF FF FF FF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0B C0 75 ?? }

    $xor_secret = { 8A ?? ?? 32 ?? 88 ?? 4? 4? E2 ?? }

    $init_function = { FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 }

    $dga_rand_int = { B9 1D F3 01 00 F7 F1 8B C8 B8 A7 41 00 00 }

    $cookies = "\\cookies4.dat"

    $s3 = "pdatesDisableNotify"

    $get_domains = { a3 [4] a1 [4] 80 3? 00 75 ?? c7 05 [4] ff ff ff ff ff 35 [4] ff 35 [4] ff 35 [4] e8 }

    $add_tld = { 55 8B EC  83 ?? ?? 57 C7 ?? ?? 00 00 00 00 B? ?? ?? ?? ?? 8B ?? ?? 3B ?? ?? 75 ?? 8B ?? }

    $get_port = { 90 68 [4] 68 [4] FF 35 [4] FF 35 [4] E8 [4] 83 }

  condition:
    $init_dga and $init_function and 2 of ($guid, $md5_magic_*, $cookies, $s3) and any of ( $get_port, $add_tld, $dga_rand_int, $get_domains, $xor_secret)
}

rule ramnit_dll {

  meta:
    author = "nazywam"
    module = "ramnit"
    reference = "https://www.cert.pl/en/news/single/ramnit-in-depth-analysis/"


  condition:
    pe.characteristics and pe.DLL and ramnit_general
}

rule ramnit_injector {

  meta:
    author = "nazywam"
    module = "ramnit"
    reference = "https://www.cert.pl/en/news/single/ramnit-in-depth-analysis/"

  strings:
    $unpack_dlls = { B8 [4] 50 E8 [4] A3 [4] 68 [4] 68 [4] FF [5] E8 [4] B8 [4] 50 E8 [4] A3 [4] 68 [4] 68 [4] FF [5] E8 }

  condition:
    $unpack_dlls and ramnit_general
}
