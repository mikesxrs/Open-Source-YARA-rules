rule skeleton_key_patcher
{
       meta:
              author = "secureworks"
              reference = "https://www.secureworks.com/research/skeleton-key-malware-analysis"

       strings:
       $target_process = "lsass.exe" wide
       $dll1 = "cryptdll.dll"
       $dll2 = "samsrv.dll"

       $name = "HookDC.dll"

       $patched1 = "CDLocateCSystem"
       $patched2 = "SamIRetrievePrimaryCredentials"
       $patched3 = "SamIRetrieveMultiplePrimaryCredentials"

       condition:
       all of them
}