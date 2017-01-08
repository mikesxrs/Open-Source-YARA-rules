rule irctelnet__loader: malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects dropper of the irctelnet - 20161102"
                //Check also: 
                // http://blog.malwaremustdie.org/2016/10/mmd-0059-2016-linuxirctelnet-new-ddos.html
                // http://tracker.h3x.eu/info/850
                // http://tracker.h3x.eu/corpus/850
                //Samples:

        strings:
                $x_00 = "mkdir -p "
                $x_01 = "&& rm -f "
                $x_02 = "ftpget -u ftp "
                $x_03 = "2>&1 ||"
                $x_04 = "wget -O"
                $x_05 = "tftp -g -r"
                $x_06 = "2>&1 &&"
                $x_07 = "chmod +x "
                $x_08 = "&& sh "

        condition:
                //Contains all of the strings
                all of ($x_*)
}

rule irctelnet__installer: malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects malicious payload of the irctelnet - 20161102"
                //Check also: 
                // http://blog.malwaremustdie.org/2016/10/mmd-0059-2016-linuxirctelnet-new-ddos.html
                // http://tracker.h3x.eu/info/850
                // http://tracker.h3x.eu/corpus/850
                //Samples:

        strings:
                $x_00 = "x32bin="
                $x_01 = "armbin="
                $x_02 = "mpsbin="
                //$x_03 = "mp1bin="
                $x_04 = "ppcbin="
                $x_05 = "sphbin="
                $x_06 = "sprbin="
                $x_07 = "ulimit -n 4096"
                $x_08 = "ip="
                $x_09 = "dir="
                $x_10 = "me="
                $x_11 = "killall -9 $"
                $x_12 = "rm -f $"
                $x_13 = "wget -O $"
                $x_14 = " && chmod +x $"
                $x_15 = " && $"
                

        condition:
                //Contains all of the strings
                all of ($x_*)
}

rule irctelnet__payload: malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects malicious payload of the irctelnet - 20161102"
                //Check also: 
                // http://blog.malwaremustdie.org/2016/10/mmd-0059-2016-linuxirctelnet-new-ddos.html
                // http://tracker.h3x.eu/info/850
                // http://tracker.h3x.eu/corpus/850
                //Samples:

        strings:
                $irc_00 = "PASS %s"
                $irc_01 = "NICK %s"
                $irc_02 = "USER %s . . : ."
                $irc_03 = "USER d3x . . : ."
                $irc_04 = "ERROR"
                $irc_05 = "-sh"
                $irc_06 = "GET / HTTP/1.0"
                $irc_07 = "Host: %s"

                $x_00 = "ogin:"
                $x_01 = "assword:"
                $x_02 = "ncorrect"
                $x_03 = "failed"
                $x_04 = "built-in commands"
                $x_05 = "seconds"
                $x_06 = "shell"
                $x_07 = "(y/N)"
                $x_08 = "free"
                $x_09 = "mkdir -p %s && rm -f %s/*; ftpget -u ftp %s %s/%s %s 2>&1 || wget -O %s/%s http://%s/%s 2>&1 || tftp -g -r "
		$x_10 = "/etc/firewall_stop"
		

        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the irc strings
                all of ($irc_*) and

                //Contains all of the specific strings
                all of ($x_*)
}

