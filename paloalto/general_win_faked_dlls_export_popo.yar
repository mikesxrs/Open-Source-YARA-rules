import "pe"

rule general_win_faked_dlls_export_popo    
{
    meta:
        author = "paloaltonetworks"
        date = "2022-03-13"
        description = "Detects DLL files with an export function named 'popo'"
        reference = "https://unit42.paloaltonetworks.com/popping-eagle-malware/"
        hash0 = "e5e89d8db12c7dacddff5c2a76b1f3b52c955c2e86af8f0b3e36c8a5d954b5e8"    // fake uxtheme.dll
        hash1 = "95676c8eeaab93396597e05bb4df3ff8cc5780ad166e4ee54484387b97f381df"   // fake uxtheme.dll
        hash2 = "59d12f26cbc3e49e28be13f0306f5a9b1a9fd62909df706e58768d2f0ccca189"    // fake uxtheme.dll
        hash3 = "0dc8f17b053d9bfab45aed21340a1f85325f79e0925caf21b9eaf9fbdc34a47a"    // ClickRuntime-amd86.dll

    condition:
        (pe.characteristics & pe.DLL) and pe.is_dll() and
        filesize < 20MB and 
        (    
             pe.exports("popo") or 
             pe.exports("Popo")
        )
	
