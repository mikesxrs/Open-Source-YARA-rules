rule apt_macOS_gimmick : StormCloud
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the macOS port of the GIMMICK malware."
        reference = "https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/"
        date = "2021-10-18"
        hash1 = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 1

    strings:
        // Also seen in DAZZLESPY
        $s1 = "http://cgi1.apnic.net/cgi-bin/my-ip.php --connect-timeout 10 -m 20" wide ascii
        
        $json1 = "base_json" ascii wide
        $json2 = "down_json" ascii wide
        $json3 = "upload_json" ascii wide
        $json4 = "termin_json" ascii wide
        $json5 = "request_json" ascii wide
        $json6 = "online_json" ascii wide
        $json7 = "work_json" ascii wide

        $msg1 = "bash_pid: %d, FDS_CHILD: %d, FDS_PARENT: %d" ascii wide
        $msg2 = "pid %d is dead" ascii wide
        $msg3 = "exit with code %d" ascii wide
        $msg4 = "recv signal %d" ascii wide

        $cmd1 = "ReadCmdQueue" ascii wide
        $cmd2 = "read_cmd_server_timer" ascii wide
        $cmd3 = "enableProxys" ascii wide
        $cmd4 = "result_block" ascii wide
        $cmd5 = "createDirLock" ascii wide
        $cmd6 = "proxyLock" ascii wide
        $cmd7 = "createDirTmpItem" ascii wide
        $cmd8 = "dowfileLock" ascii wide
        $cmd9 = "downFileTmpItem" ascii wide
        $cmd10 = "filePathTmpItem" ascii wide
        $cmd11 = "uploadItems" ascii wide
        $cmd12 = "downItems" ascii wide
        $cmd13 = "failUploadItems" ascii wide
        $cmd14 = "failDownItems" ascii wide
        $cmd15 = "downloadCmds" ascii wide
        $cmd16 = "uploadFiles" ascii wide

    condition:
        $s1 or 
        5 of ($json*) or 
        3 of ($msg*) or 
        9 of ($cmd*)
}


