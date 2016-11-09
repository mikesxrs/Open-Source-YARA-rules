rule Neurevt {
        meta:
                author = "Venom23"
                date = "2013-06-21"
                description = "Neurevt Malware Sig"
                hash0 = "db9a816d58899f1ba92bc338e89f856a"
                hash1 = "d7b427ce3175fa7704da6b19a464938e"
                hash2 = "13027beb8aa5e891e8e641c05ccffde3"
                hash3 = "d1004b63d6d3cb90e6012c68e19ab453"
                hash4 = "a1286fd94984fd2de857f7b846062b5e"
                yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
        strings:
                $string0 = "BullGuard" wide
                $string1 = "cmd.exe" wide
                $string4 = "eUSERPROFILE" wide
                $string5 = "%c:\\%s.lnk" wide
                $string6 = "services.exe" wide
                $string9 = "Multiples archivos corruptos han sido encontrados en la carpeta \"Mis Documentos\". Para evitar perder" wide
                $string10 = "F-PROT Antivirus Tray application" wide
                $string12 = "-k NetworkService" wide
                $string13 = "firefox.exe"
                $string14 = "uWinMgr.exe" wide
                $string15 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.13) Gecko/20060410 Firefox/1.0.8"
                $string16 = "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11"
                $string18 = "Data Path" wide
        condition:
                10 of them
}