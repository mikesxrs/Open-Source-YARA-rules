/*
# 14ECD5E6FC8E501037B54CA263896A11 @ 0x80C2660
>>> data = '2D72647852323138502E2930216A76242521717E7F7C3B213D2E670559404646400F07475B0A0359495E74010308076915101708415F0B0C0A58592627627E64753E62302B2F29296400'.decode('hex')
>>> def decode(s):
    result = ''
    for i in xrange(len(s) - 5):
        result += chr(ord(s[i]) ^ (i + 5))
    return result

>>> decode(data)
'(tcp[8:4] & 0xe007ffff = 0x%xbebe) or (udp[12:4] & 0xe007ffff = 0x%xb'
>>> 

*/
// linux apt backdoor
rule turla {
    strings:
        // 14ECD5E6FC8E501037B54CA263896A11 @ 0x084680
        $xor_loop = { 8d4a05 328a ???????? 888a ???????? 42 83fa08 76eb }
        // 14ECD5E6FC8E501037B54CA263896A11 @ 0x80c2660
        $enc_string = { 2D72647852323138502E2930216A76 }

    condition:
        any of them
}

