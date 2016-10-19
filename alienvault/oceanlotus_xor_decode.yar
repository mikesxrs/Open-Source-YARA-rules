rule oceanlotus_xor_decode
{
        meta:
               author = "AlienVault Labs"
               type = "malware"
               description = "OceanLotus XOR decode function"
               reference = "https://www.alienvault.com/blogs/labs-research/oceanlotus-for-os-x-an-application-bundle-pretending-to-be-an-adobe-flash-update"
    strings:
        $xor_decode = { 89 D2 41 8A ?? ?? [0-1] 32 0? 88 ?? FF C2 [0-1] 39 ?A [0-1] 0F 43 D? 4? FF C? 48 FF C? [0-1] FF C? 75 E3 }
    condition:
        $xor_decode
}