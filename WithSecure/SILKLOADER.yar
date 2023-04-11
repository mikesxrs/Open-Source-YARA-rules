import "pe"
rule SILKLOADER
{
    meta:
        author="WithSecure"
        description="Detects SILKLOADER samples"
        date="2023-03-15"
        version="1.0"
        reference="https://labs.withsecure.com/publications/silkloader"
        hash1="c83ac6dc96febd49c7c558e8cf85dd8bcb3a84fdc78b3ba72ebf681566dc1865"
        hash2="e4dadabd1cee7215ff6e31e01f6b0dd820851685836592a14f982f2c7972fc25"
        hash3="d77a59e6ba3a8f3c000a8a8955af77d2898f220f7bf3c0968bf0d7c8ac25a5ad"
        report = "https://www.withsecure.com/content/dam/with-secure/ja/news-library/20230316_WithSecure_Silkloader_Report_ENG.pdf"
    strings:
        $str1 = {5400520041004e005300460045005200}
        $str2 = {760062006300630073006200}
    condition:
        pe.is_pe
        and pe.characteristics & pe.DLL
        and all of them
}