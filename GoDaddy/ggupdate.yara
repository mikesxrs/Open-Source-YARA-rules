rule ggupdate_windows {
    meta:
        description = "ggupdate.exe keylogger (Windows)"

    strings:
        // 9706A7D1479EB0B5E60535A952E63F1A
        // these strings are located in the packer or are unprotected
        $s1 = "Les Blues"
        $s2 = "lesblues.exe"
        $s3 = "Boodled8"
        $s4 = "Misexplain6"
        $s5 = "lesblues"
        $s6 = "Sniffs5"
        $s7 = "Oneiromancy"
        $s8 = "Lophtcrack" ascii wide

    condition:
        IsPeFile and 3 of them
}


rule ggupdate_linux {
    meta:
        description = "ggupdate keylogger (Linux)"

    strings:
        // 4611DAA8CF018B897A76FBAB51665C62
        $s1 = "%s.Identifier"
        $s2 = "0:%llu:%s;"
        $s3 = "%s%.2d-%.2d-%.4d"
        $s4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"

    condition:
        IsElfFile and 3 of them
}


