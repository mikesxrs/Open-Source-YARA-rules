private rule _fat
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"

    //  0   belong      0xcafebabe
    //  >4  belong      1       Mach-O universal binary with 1 architecture
    //  >4  belong      >1
    //  >>4 belong      <20     Mach-O universal binary with %ld architectures
 
    strings:
        $fat = { CA FE BA BE }
 
    condition:
        $fat at 0 and uint32(4) < 0x14000000
}
 
private rule _macho
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"

    strings:
        $macho1 = { CE FA ED FE }   // Little Endian
        $macho2 = { CF FA ED FE }   // Little Endian 64
        $macho3 = { FE ED FA CE }   // Big Endian
        $macho4 = { FE ED FA CF }   // Big Endian 64
 
    condition:
        for any of ( $macho* ) : ( $ at 0 ) or _fat
}
 
rule lib_jb
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"

    strings:
        $import = "libguiinject.dylib"
 
    condition:
        _macho and $import
}
 
rule app_jb
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"

    strings:
        $import1 = "@executable_path/jailbreak" nocase
        $import2 = "@executable_path/patch" nocase
 
    condition:
        _macho and any of ( $import* )
}
 
rule ipa_jb
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"
        
    strings:
        $zip = "PK"
        $import1 = ".app/jailbreak" nocase
        $import2 = ".app/patch" nocase
 
    condition:
        $zip at 0 and any of ( $import* )
}