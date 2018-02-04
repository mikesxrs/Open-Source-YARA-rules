rule BLACKMOON_BANKER {

    meta:

        author = "Proofpoint Staff"

        info = "blackmoon update"

		reference = "https://www.proofpoint.com/us/threat-insight/post/Updated-Blackmoon-Banking-Trojan"
 

        strings:

                $s1 = "BlackMoon RunTime Error:" nocase wide ascii

                $s2 = "\\system32\\rundll32.exe" wide ascii

                $s3 = "cmd.exe /c ipconfig /flushdns" wide ascii

                $s4 = "\\system32\\drivers\\etc\\hosts.ics" wide ascii

        condition:

                all of them

}
