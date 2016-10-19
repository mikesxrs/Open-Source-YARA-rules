
rule libgcc_backdoor {
    strings:
        // Decode:
        // >>> def sar(value, n):
        //     return  value >> n if (value & 0x80000000) == 0 else (value >> n) | (0xFFFFFFFF << (32-n))
        // >>> def decode(s):
        //     key = 'BB2FA36AAA9541F0'
        //     result = ''
        //     for i in xrange(len(s)):
        //         ecx = i
        //         eax = ecx
        //         eax = sar(eax, 0x1F)
        //         eax &= 0xFFFFFFFF
        //         eax >>= 0x1C
        //         edx = ecx+eax
        //         edx &= 0x0F
        //         edx -= eax
        //         eax = ord(key[edx])
        //         result += chr(ord(s[i]) ^ eax)
        //     return result

        // File EAF2CF628D1DBC78B97BAFD7A9F4BEE4
        $decode_fn = { 89C8C1F81FC1E81C8D140183E20F29C20FB682????????30041983C10139F175DF }
        $decryption_key = "BB2FA36AAA9541F0"
        $function1 = "exec_packet"
        $function2 = "build_udphdr"
        $function3 = "build_tcphdr"
        $function4 = "http_download_mem"
        $function5 = "daemon_get_kill_process"


    condition:
        IsElfFile and ($decode_fn or $decryption_key or all of ($function*))
}

