
rule virtualbox_detection {
    strings:
        $s1 = "HARDWARE\\ACPI\\DSDT\\VBOX__" nocase wide ascii
        $s2 = "\\\\.\\VBoxMiniRdrDN" nocase wide ascii
        $s3 = "VBoxHook.dll" nocase wide ascii
        $s4 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase wide ascii
        $s5 = "SYSTEM\\CurrentControlSet\\Enum\\IDE" nocase wide ascii
        $s6 = "HARDWARE\\DESCRIPTION\\System" nocase wide ascii
        $s7 = "SystemBiosVersion" nocase wide ascii
        $s8 = "VideoBiosVersion" nocase wide ascii

    condition:
        IsPeFile and 5 of ($s*)
}

