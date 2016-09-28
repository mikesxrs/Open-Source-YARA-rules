rule derusbi_kernel
{
    meta:
        description = "Derusbi Driver version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
        reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
    strings:
    $token1 = "$$$--Hello"     
    $token2 = "Wrod--$$$"   
    $cfg = "XXXXXXXXXXXXXXX"
    $class = ".?AVPCC_BASEMOD@@"
    $MZ = "MZ"

    condition:
        $MZ at 0 and $token1 and $token2 and $cfg and $class
}