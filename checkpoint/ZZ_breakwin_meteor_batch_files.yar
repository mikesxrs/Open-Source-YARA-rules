rule ZZ_breakwin_meteor_batch_files {
    meta:
        description = "Detect the batch files used in the attacks"
        reference = "https://research.checkpoint.com/2021/indra-hackers-behind-recent-attacks-on-iran/"
        author = "Check Point Research"
        date = "22-07-2021"
    strings:
        $filename_0 = "mscap.bmp"
        $filename_1 = "mscap.jpg"
        $filename_2 = "msconf.conf"
        $filename_3 = "msmachine.reg"
        $filename_4 = "mssetup.exe"
        $filename_5 = "msuser.reg"
        $filename_6 = "msapp.exe"
        $filename_7 = "bcd.rar"
        $filename_8 = "bcd.bat"
        $filename_9 = "msrun.bat"
        $command_line_0 = "powershell -Command \"%exclude_command% '%defender_exclusion_folder%"
        $command_line_1 = "start /b \"\" update.bat hackemall"
    condition:
        4 of ($filename_*) or
        any of ($command_line_*)
}
