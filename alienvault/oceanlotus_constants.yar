rule oceanlotus_constants
{
        meta:
               author = "AlienVault Labs"
               type = "malware"
               description = "OceanLotus constants"
               reference = "https://www.alienvault.com/blogs/labs-research/oceanlotus-for-os-x-an-application-bundle-pretending-to-be-an-adobe-flash-update"
    strings:
        $c1 = { 3A 52 16 25 11 19 07 14 3D 08 0F }
        $c2 = { 0F 08 3D 14 07 19 11 25 16 52 3A }
    condition:
        any of them
}
 