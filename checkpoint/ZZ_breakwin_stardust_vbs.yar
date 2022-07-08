rule ZZ_breakwin_stardust_vbs {
    meta:
        description = "Detect the VBS files that where found in the attacks on targets in Syria"
        reference = "https://research.checkpoint.com/2021/indra-hackers-behind-recent-attacks-on-iran/"
        author = "Check Point Research"
        date = "22-07-2021"
        hash = "38a419cd9456e40961c781e16ceee99d970be4e9235ccce0b316efe68aba3933"
        hash = "62a984981d14b562939294df9e479ac0d65dfc412d0449114ccb2a0bc93769b0"
        hash = "4d994b864d785abccef829d84f91d949562d0af934114b65056315bf59c1ef58"
        hash = "eb5237d56c0467b5def9a92e445e34eeed9af2fee28f3a2d2600363724d6f8b0"
        hash = "5553ba3dc141cd63878a7f9f0a0e67fb7e887010c0614efd97bbc6c0be9ec2ad"
    strings:
        $url_template = "progress.php?hn=\" & CN & \"&dt=\" & DT & \"&st="
        $compression_password_1 = "YWhZMFU1VlZGdGNFNWlhMVlVMnhTMWtOVlJVWWNGTk9iVTQxVW10V0ZFeFJUMD0r"
        $compression_password_2 = "YWlvcyBqQCNAciNxIGpmc2FkKnIoOUZURjlVSjBSRjJRSlJGODlKSDIzRmloIG8"
        $uninstall_kaspersky = "Shell.Run \"msiexec.exe /x \" & productcode & \" KLLOGIN="
        $is_avp_running = "isProcessRunning(\".\", \"avp.exe\") Then"
    condition:
        any of them
}
