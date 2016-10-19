
rule aspack {
    meta:
        description = "ASPack packed file"
        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $aspack_section = {2E61737061636B00}
        $adata_section = {2E61646174610000}

    condition:
        $mz at 0 and $aspack_section at 0x248 and $adata_section at 0x270
}

