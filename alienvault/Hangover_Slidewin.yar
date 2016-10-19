rule Hangover_Slidewin {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "[NumLock]"
        $a2 = "[ScrlLock]"
        $a3 = "[LtCtrl]"
        $a4 = "[RtCtrl]"
        $a5 = "[LtAlt]"
        $a6 = "[RtAlt]"
        $a7 = "[HomePage]"
        $a8 = "[MuteOn/Off]"
        $a9 = "[VolDn]"
        $a10 = "[VolUp]"
        $a11 = "[Play/Pause]"
        $a12 = "[MailBox]"
        $a14 = "[Calc]"
        $a15 = "[Unknown]"
        
    condition:
        all of them

}


