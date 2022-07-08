rule Gozi_JJ_struct: trojan {
    meta:
        module = "Gozi_JJ_struct"
        reference = "https://research.checkpoint.com/2020/gozi-the-malware-with-a-thousand-faces/"
    strings:
        $jj = "JJ" ascii
        $pe_file = "This program cannot be run in DOS mode" ascii
        $bss = ".bss" ascii
    condition:
         #jj >= 2 and (for all i in (1,2) : (@jj[i] < 0x400 and @jj[i] > 0x200)) and (@jj[2] - @jj[1] == 0x14) and ($pe_file in (0..1000)) and ($bss in (0..1000))
}
