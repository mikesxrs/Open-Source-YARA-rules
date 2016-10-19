
rule billgates {
    strings:
        // D66EA6D84F04358925DC220003997BD8 @ 0804B4B6
        $decrypt = { 5589E583EC10C745FC00000000EB378B45FC83E00184C074158B45FC89C20355088B45FC0345108A00408802EB138B45FC89C20355088B45FC0345108A004888028D45FCFF008B45FC3B45147D148B45FC3B450C7D0C8B45FC0345108A0084C075ADC9C3 }

        // BDA324786F1E8212A11F6AC5C612FB1E
        $source_file1 = "AmpResource.cpp"
        $source_file2 = "Attack.cpp"
        $source_file3 = "AutoLock.cpp"
        $source_file4 = "CmdMsg.cpp"
        $source_file5 = "ExChange.cpp"
        $source_file6 = "MiniHttpHelper.cpp"
        $source_file7 = "NetBase.cpp"
        $source_file8 = "ProtocolUtil.cpp"
        $source_file9 = "ProvinceDns.cpp"
        $source_file10 = "RSA.cpp"
        $source_file11 = "StatBase.cpp"
        $source_file12 = "ThreadAtk.cpp"
        $source_file13 = "ThreadClientStatus.cpp"
        $source_file14 = "ThreadFakeDetect.cpp"
        $source_file15 = "ThreadHttpGet.cpp"
        $source_file16 = "ThreadLoopCmd.cpp"
        $source_file17 = "ThreadMonGates.cpp"
        $source_file18 = "ThreadMutex.cpp"
        $source_file19 = "ThreadShell.cpp"
        $source_file20 = "UserAgent.cpp"
        $source_file21 = "WinDefSVC.cpp"

        $string1 = "AppleWebKit"
        $string2 = "/etc/rc%d.d/S%d%s"
        $string3 = "/tmp/gates.lock"
        $string4 = "chmod 0755 %s"
        $string5 = "%7s %llu %lu %lu %lu %lu %lu %lu %lu %llu %lu %lu %lu %lu %lu %lu"
        $string6 = "cpu %llu %llu %llu %llu"
        $string7 = "libamplify.so"
        $string8 = "/tmp/moni.lock"
        $string9 = "/usr/bin/.sshd"
        
    condition:
        IsElfFile and ($decrypt or 10 of ($source_file*) or 7 of ($string*))
}

