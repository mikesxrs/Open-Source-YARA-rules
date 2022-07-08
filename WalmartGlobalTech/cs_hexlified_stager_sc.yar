rule cs_hexlified_stager_sc
{
meta:
reference = "https://medium.com/walmartglobaltech/cobaltstrike-uuid-stager-ca7e82f7bb64"
strings:
$a1 = "d2648b52308b" nocase
condition:
all of them
}


