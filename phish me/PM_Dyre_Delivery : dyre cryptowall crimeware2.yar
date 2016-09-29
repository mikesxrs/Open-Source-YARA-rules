rule PM_Dyre_Delivery1 : dyre cryptowall crimeware
{
meta:
    author="R.Tokazowski"
    company="PhishMe, Inc."
    URL="http://phishme.com/dyre-attackers-shift-tactics/"

strings:
    $domain1 = "goo.gl" nocase
    $domain2 = "cubby.com" nocase
    $domain3 = "dropbox.com" nocase
        $php = ".php" nocase

    $subject1 = "fax" nocase
    $subject2 = "message" nocase
        $subject3 = "voice" nocase

    $constant = "Resolution: 400x400 DPI" nocase

        $eh1 = "(EHLO fax-voice.com)"
        $eh2 = "(EHLO voiceservice.com)"
        $eh3 = "(EHLO MyFax.com)"

       $anchor = "EHLO"

condition:

    (1 of ($domain*) and 1 of ($subject*)) or 
        ($constant and 1 of ($domain*)) or 
        (all of ($subject*) and $php) or
        (2 of ($subject*) and $php) or
        any of ($eh*) or
        ($subject1 in (@anchor..@anchor+20)) or
        ($subject3 in (@anchor..@anchor+20))

}