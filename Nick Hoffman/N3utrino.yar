rule N3utrino
{
    meta:
        Author = "Nick Hoffman"
        Description = "Detects versions of Neutrino malware"
        ref = "http://www.morphick.com/resources/lab-blog/evening-n3utrino"

    strings:
        $post_host_information = "getcmd=1&uid=%s&os=%s&av=%s&nat=%s&version=%s&serial=%s&quality=%i"
        $post_cc_information = "dumpgrab=1&track_type=%s&track_data=%s&process_name=%s"
    $post_taskexec = "taskexec=1&task_id=%s"
    $post_taskfail = "taskfail=1&task_id=%s"
    
        $command1 = "loader"
        $command2 = "findfile"
        $command3 = "spread"
        $command4 = "archive"
        $command5 = "usb"
        $command6 = "botkiller"
        $command7 = "dwflood"
        $command8 = "keylogger"
    condition:
        4 of ($command*) or any of ($post*)
}