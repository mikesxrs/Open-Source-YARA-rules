
rule command_shell {
    meta:
        description = "Microsoft Windows Command Shell"

        Block = false
        Quarantine = false

    strings:
        $internal_error = "CMD Internal Error %s"
        $shell_open_command = "\\Shell\\Open\\Command" ascii wide
        $mklink = "ENDLOCAL" ascii wide
        $errorlevel = "ERRORLEVEL" ascii wide
        $cmdextversion = "CMDEXTVERSION" ascii wide
        $dpath = "DPATH" ascii wide
        $color = "COLOR" ascii wide
        $chdir = "CHDIR" ascii wide
        $pushd = "PUSHD" ascii wide
        $ftype = "FTYPE" ascii wide
        $erase = "ERASE" ascii wide
        $defined = "DEFINED" ascii wide
        $prompt = "PROMPT" ascii wide
        $setlocal = "SETLOCAL" ascii wide

    condition:
        IsPeFile and all of them
}

