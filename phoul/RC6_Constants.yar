rule RC6_Constants {
        meta:
                author = "chort (@chort0)"
                description = "Look for RC6 magic constants in binary"
                reference = "https://twitter.com/mikko/status/417620511397400576"
                reference2 = "https://twitter.com/dyngnosis/status/418105168517804033"
                date = "2013-12"
                version = "0.2"
        strings:
                $c1 = { B7E15163 }
                $c2 = { 9E3779B9 }
                $c3 = { 6351E1B7 }
                $c4 = { B979379E }
        condition:
                2 of them
}