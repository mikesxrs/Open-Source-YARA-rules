rule apt_rb_rokrat_loader : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        description = "Ruby loader seen loading the ROKRAT malware family."
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        date = "2021-06-22"
        hash1 = "5bc52f6c1c0d0131cee30b4f192ce738ad70bcb56e84180f464a5125d1a784b2"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $magic1 = "'https://update.microsoft.com/driverupdate?id=" ascii wide
        $magic2 = "sVHZv1mCNYDO0AzI';" ascii wide
        $magic3 = "firoffset..scupd.size" ascii wide
        $magic4 = /alias UrlFilter[0-9]{2,5} eval;"/
        
        // Original: 'Fiddle::Pointer' (Reversed)
        $s1 = "clRnbp9GU6oTZsRGZpZ"
        $s2 = "RmlkZGxlOjpQb2ludGVy"
        $s3 = "yVGdul2bQpjOlxGZklmR"
        $s4 = "XZ05WavBlO6UGbkRWaG"

    condition:
        any of ($magic*) or
        any of ($s*)
}
