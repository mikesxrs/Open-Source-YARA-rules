rule petya_eternalblue : petya_eternalblue {
    meta:
        author      = "blueliv"
        description =  "Based on spreading petya version: 2017-06-28"
        reference = "https://blueliv.com/petya-ransomware-cyber-attack-is-spreading-across-the-globe-part-2/"
    strings:
        /* Some commands executed by the Petya variant */
       $cmd01 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%0" wide
       $cmd02 = "shutdown.exe /r /f" wide
       $cmd03 = "%s \\\\%s -accepteula -s" wide
       $cmd04 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1" wide
       /* Strings of encrypted files */
       $str01 = "they have been encrypted. Perhaps you are busy looking" wide
        /* MBR/VBR payload */
        $mbr01 = {00 00 00 55 aa e9 ?? ??}
    condition:
        all of them
}
