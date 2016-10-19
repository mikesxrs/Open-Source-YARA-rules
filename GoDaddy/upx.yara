
rule upx {
    meta:
        description = "UPX packed file"

        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}
        $upx_sig = "UPX!"

    condition:
        $mz at 0 and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024)
}

