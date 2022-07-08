rule explosive_exe
{
  meta:
    author = "Check Point Software Technologies Inc."
    info = "Explosive EXE"
  strings:
    $MZ = "MZ"
    $DLD_S = "DLD-S:"
    $DLD_E = "DLD-E:"
  condition:
    $MZ at 0 and all of them
}

import "pe"
rule explosive_dll

{
  meta:
    author = "Check Point Software Technologies Inc."
    info = "Explosive DLL"
    reference = "https://www.checkpoint.com/downloads/volatile-cedar-technical-report.pdf"

 
  condition:
    pe.DLL
    and ( pe.exports("PathProcess") or pe.exports("_PathProcess@4") ) and 
pe.exports("CON")
}

rule ZZ_breakwin_config {
    meta:
        description = "Detects the header of the encrypted config files, assuming known encryption key."
        reference = "https://research.checkpoint.com/2021/indra-hackers-behind-recent-attacks-on-iran/"
        author = "Check Point Research"
        date = "22-07-2021"
        hash = "948febaab71727217303e0aabb9126f242aa51f89caa7f070a3da76c4f5699ed"
        hash = "2d35bb7c02062ff2fba4424a267c5c83351405281a1870f52d02f3712a547a22"
        hash = "68e95a3ccde3ea22b8eb8adcf0ad53c7993b2ea5316948e31d9eadd11b5151d7"
    strings:
        $conf_header = {1A 69 45 47 5E 46 4A 06 03 E4 34 0B 06 1D ED 2F 02 15 02 E5 57 4D 59 59 D1 40 20 22}
    condition:
        $conf_header at 0
}
rule ZZ_breakwin_wiper {
    meta:
        description = "Detects the BreakWin wiper that was used in attacks in Syria"
        reference = "https://research.checkpoint.com/2021/indra-hackers-behind-recent-attacks-on-iran/"
        author = "Check Point Research"
        date = "22-07-2021"
        hash = "2aa6e42cb33ec3c132ffce425a92dfdb5e29d8ac112631aec068c8a78314d49b"
        hash = "6709d332fbd5cde1d8e5b0373b6ff70c85fee73bd911ab3f1232bb5db9242dd4"
        hash = "d71cc6337efb5cbbb400d57c8fdeb48d7af12a292fa87a55e8705d18b09f516e"
    strings:
        $debug_str_meteor_1 = "the program received an invalid number of arguments" wide
        $debug_str_meteor_2 = "End interval logger. Resuming writing every log" wide
        $debug_str_meteor_0 = "failed to initialize configuration from file" wide
        $debug_str_meteor_3 = "Meteor is still alive." wide
        $debug_str_meteor_4 = "Exiting main function because of some error" wide
        $debug_str_meteor_5 = "Meteor has finished. This shouldn't be possible because of the is-alive loop." wide
        $debug_str_meteor_6 = "Meteor has started." wide
        $debug_str_meteor_7 = "Could not hide current console." wide
        $debug_str_meteor_8 = "Could not get the window handle used by the console." wide
        $debug_str_meteor_9 = "Failed to find base-64 data size" wide
        $debug_str_meteor_10 = "Running locker thread" wide
        $debug_str_meteor_11 = "Failed to encode wide-character string as Base64" wide
        $debug_str_meteor_12 = "Wiper operation failed." wide
        $debug_str_meteor_13 = "Screen saver disable failed." wide
        $debug_str_meteor_14 = "Failed to generate password of length %s. Generating a default one." wide
        $debug_str_meteor_15 = "Failed to delete boot configuration" wide
        $debug_str_meteor_16 = "Could not delete all BCD entries." wide
        $debug_str_meteor_17 = "Finished deleting BCD entries." wide
        $debug_str_meteor_18 = "Failed to change lock screen" wide
        $debug_str_meteor_19 = "Boot configuration deleted successfully" wide
        $debug_str_meteor_20 = "Failed to kill all winlogon processes" wide
        $debug_str_meteor_21 = "Changing passwords of all users to" wide
        $debug_str_meteor_22 = "Failed to change the passwords of all users" wide
        $debug_str_meteor_23 = "Failed to run the locker thread" wide
        $debug_str_meteor_24 = "Screen saver disabled successfully." wide
        $debug_str_meteor_25 = "Generating random password failed" wide
        $debug_str_meteor_26 = "Locker installation failed" wide
        $debug_str_meteor_27 = "Failed to set auto logon." wide
        $debug_str_meteor_28 = "Failed to initialize interval logger. Using a dummy logger instead." wide
        $debug_str_meteor_29 = "Succeeded setting auto logon for" wide
        $debug_str_meteor_30 = "Failed disabling the first logon privacy settings user approval." wide
        $debug_str_meteor_31 = "Failed disabling the first logon animation." wide
        $debug_str_meteor_32 = "Waiting for new winlogon process" wide
        $debug_str_meteor_33 = "Failed to isolate from domain" wide
        $debug_str_meteor_34 = "Failed creating scheduled task for system with name %s." wide
        $debug_str_meteor_35 = "Failed to get the new token of winlogon." wide
        $debug_str_meteor_36 = "Failed adding new admin user." wide
        $debug_str_meteor_37 = "Failed changing settings for the created new user." wide
        $debug_str_meteor_38 = "Failed disabling recovery mode." wide
        $debug_str_meteor_39 = "Logging off users on Windows version 8 or above" wide
        $debug_str_meteor_40 = "Succeeded setting boot policy to ignore all errors." wide
        $debug_str_meteor_41 = "Succeeded creating scheduled task for system with name" wide
        $debug_str_meteor_42 = "Succeeded disabling recovery mode" wide
        $debug_str_meteor_43 = "Failed to log off all sessions" wide
        $debug_str_meteor_44 = "Failed to delete shadowcopies." wide
        $debug_str_meteor_45 = "Failed logging off session: " wide
        $debug_str_meteor_46 = "Failed setting boot policy to ignore all errors." wide
        $debug_str_meteor_47 = "Successfully logged off all local sessions, except winlogon." wide
        $debug_str_meteor_48 = "Succeeded creating scheduled task with name %s for user %s." wide
        $debug_str_meteor_49 = "Killing all winlogon processes" wide
        $debug_str_meteor_50 = "Logging off users in Windows 7" wide
        $debug_str_meteor_51 = "Failed logging off all local sessions, except winlogon." wide
        $debug_str_meteor_52 = "Failed creating scheduled task with name %s for user %s." wide
        $debug_str_meteor_53 = "Succeeded deleting shadowcopies." wide
        $debug_str_meteor_54 = "Logging off users in Windows XP" wide
        $debug_str_meteor_55 = "Failed changing settings for the created new user." wide
        $debug_str_meteor_56 = "Could not open file %s. error message: %s" wide
        $debug_str_meteor_57 = "Could not write to file %s. error message: %s" wide
        $debug_str_meteor_58 = "tCould not tell file pointer location on file %s." wide
        $debug_str_meteor_59 = "Could not set file pointer location on file %s to offset %s." wide
        $debug_str_meteor_60 = "Could not read from file %s. error message: %s" wide
        $debug_str_meteor_61 = "Failed to wipe file %s" wide
        $debug_str_meteor_62 = "attempted to access encrypted file in offset %s, but it only supports offset 0" wide
        $debug_str_meteor_63 = "Failed to create thread. Error message: %s" wide
        $debug_str_meteor_64 = "Failed to wipe file %s" wide
        $debug_str_meteor_65 = "failed to get configuration value with key %s" wide
        $debug_str_meteor_66 = "failed to parse the configuration from file %s" wide
        $debug_str_meteor_67 = "Failed posting to server, received unknown exception" wide
        $debug_str_meteor_68 = "Failed posting to server, received std::exception" wide
        $debug_str_meteor_69 = "Skipping %s logs. Writing log number %s:" wide
        $debug_str_meteor_70 = "Start interval logger. Writing logs with an interval of %s logs." wide
        $debug_str_meteor_71 = "failed to write message to log file %s" wide
        $debug_str_meteor_72 = "The log message is too big: %s/%s characters." wide
        $debug_str_stardust_0 = "Stardust has started." wide
        $debug_str_stardust_1 = "0Vy0qMGO" ascii wide
        $debug_str_comet_0 = "Comet has started." wide
        $debug_str_comet_1 = "Comet has finished." wide
        $str_lock_my_pc = "Lock My PC 4" ascii wide
        $config_entry_0 = "state_path" ascii
        $config_entry_1 = "state_encryption_key" ascii
        $config_entry_2 = "log_server_port" ascii
        $config_entry_3 = "log_file_path" ascii
        $config_entry_4 = "log_encryption_key" ascii
        $config_entry_5 = "log_server_ip" ascii
        $config_entry_6 = "processes_to_kill" ascii
        $config_entry_7 = "process_termination_timeout" ascii
        $config_entry_8 = "paths_to_wipe" ascii
        $config_entry_9 = "wiping_stage_logger_interval" ascii
        $config_entry_10 = "locker_exe_path" ascii
        $config_entry_11 = "locker_background_image_jpg_path" ascii
        $config_entry_12 = "auto_logon_path" ascii
        $config_entry_13 = "locker_installer_path" ascii
        $config_entry_14 = "locker_password_hash" ascii
        $config_entry_15 = "users_password" ascii
        $config_entry_16 = "locker_background_image_bmp_path" ascii
        $config_entry_17 = "locker_registry_settings_files" ascii
        $config_entry_18 = "cleanup_script_path" ascii
        $config_entry_19 = "is_alive_loop_interval" ascii
        $config_entry_20 = "cleanup_scheduled_task_name" ascii
        $config_entry_21 = "self_scheduled_task_name" ascii
        $encryption_asm = {33 D2 8B C3 F7 75 E8 8B 41 04 8B 4E 04 8A 04 02 02 C3 32 04 1F 88 45 F3 39 4E 08}
        $random_string_generation = {33 D2 59 F7 F1 83 ?? ?? 08 66 0F BE 82 ?? ?? ?? 00 0F B7 C8 8B C7}
    condition:
        uint16(0) == 0x5A4D and
        (
                6 of them or
                $encryption_asm or 
                $random_string_generation
        )
}
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
