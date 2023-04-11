import "pe"
rule ducktail_nativeaot
{
    meta:
        author="WithSecure"
        description="Detects NativeAOT variants of DUCKTAIL malware"
        date="2022-11-17"
        version="1.0"
        reference="https://labs.withsecure.com/publications/ducktail_returns"
        hash1="b043e4639f89459cae85161e6fbf73b22470979e"
        hash2="073b092bf949c31628ee20f7458067bbb05fda3a"
        hash3="d1f6b5f9718a2fe9eaac0c1a627228d3f3b86f87"
        report = "https://www.withsecure.com/en/expertise/research-and-innovation/research/ducktail-an-infostealer-malware"
     condition:
        uint16(0) == 0x5A4D
        and filesize > 15MB
        and (pe.section_index(".managed") >= 0
            or pe.exports("DotNetRuntimeDebugHeader")
        )
        and pe.exports("SendFile")
        and pe.exports("Start")
        and pe.exports("Open")
}