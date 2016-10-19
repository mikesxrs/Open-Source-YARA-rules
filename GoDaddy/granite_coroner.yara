
rule granite_coroner_dropper {
    meta:
        description = "Payload dropper for password theft or keylogging"

    strings:
        $mz = "MZ"

        // 5222D4EE744464B154505E68579EB896 - Resource names
        $granitea = "GRANITE" nocase
        $granitew = "GRANITE" nocase wide
        $jocastaeluviuma = "JOCASTAELUVIUM" nocase
        $jocastaeluviumw = "JOCASTAELUVIUM" nocase wide

        // FA620D788F4E9B22B603276EB020AA8C - Resource names
        $coronera = "CORONER" nocase
        $coronerw = "CORONER" nocase wide
        $bolshiecharitya = "BOLSHIECHARITY" nocase
        $bolshiecharityw = "BOLSHIECHARITY" nocase wide

        // Both
        $cypher_cryptor = "Cypher Cryptor" wide

    condition:
        $mz at 0 and 
            ($granitea and $jocastaeluviuma) or
            ($granitew and $jocastaeluviumw) or
            ($coronera and $bolshiecharitya) or
            ($coronerw and $bolshiecharityw) or
        $cypher_cryptor
}

rule granite_jocasteluvium {
    strings:
        $mz = "MZ"

        // 8B805E07CCA42BE8FC98C8BCF8D0C7C2
        $string1 = "JumpID(\"\",\"%s\")"
        $string2 = " - Clipboard - "
        $string3 = "Content-Type: application/x-www-form-urlencoded"
        $string4 = "text="
        $string5 = "[Num Lock]"
        $string6 = "[PrtScr]"
        $string7 = "msgss.exe"
        $string8 = "User Interface Manager" wide

    condition:
        $mz at 0 and 7 of ($string*)
}


rule coroner_bolshiecharity {
    meta:
        description = "Password extraction utility"

    strings:
        $mz = "MZ"
        // list of default passwords in 907B3FD96072ADCD08BB6ACA4BD07FC1 @ 0x4146b1
        $passwords = "chelsea\x0055555\x00angel1\x00hardcore\x00dexter\x00saved\x00112233\x00hallo\x00"

    condition:
        $mz at 0 and $passwords
}

