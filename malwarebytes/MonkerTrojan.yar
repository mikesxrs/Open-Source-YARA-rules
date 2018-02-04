rule MokerTrojan
{ 
meta:
 author = "malwarebytes"
 reference = "https://blog.malwarebytes.com/threat-analysis/2017/04/elusive-moker-trojan/"
strings:
 $mz = "MZ"
 $key = {3D FF 24 8B 92 C1 D6 9D}

condition: 
 $mz at 0 and uint32(uint32(0x3C)) == 0x455 and $key
}
