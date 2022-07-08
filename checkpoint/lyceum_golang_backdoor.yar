rule lyceum_golang_backdoor
{
    meta:
        author = "CPR"
        reference = "https://research.checkpoint.com/2022/state-sponsored-attack-groups-capitalise-on-russia-ukraine-war-for-cyber-espionage/"
        hash1 = "a437f997d45bc14e76d0f2482f572a34"
        hash2 = "23d174e6a0905fd59b2613d5ac106261"
        hash3 = "bcb465cc2257e5777bab431690ca5039"
    strings:
        $func1 = "main.Ase256"
        $func2 = "main.DecryptAse256"
        $func3 = "main.IsServerUp"
        $func4 = "main.register"
        $func5 = "main.commandforrun"
        $func6 = "main.UPLOAD"
        $func7 = "main.commandforanswer"
        $func8 = "main.GetMD5Hash"
        $func9 = "main.get_uid"
        $func10 = "main.commandrun"
        $func11 = "main.download"
        $func12 = "main.postFile"
        $func13 = "main.sendAns"
        $func14 = "main.comRun"
        $cnc_uri1 = "/GO/1.php"
        $cnc_uri2 = "/GO/2.php"
        $cnc_uri3 = "/GO/3.php"
        $auth_token = "auth_token=\"XXXXXXX\""
        $log1 = "client registred"
        $log2 = "no command"
        $log3 = "can not create file"
        $log4 = "errorGettingUserName"
        $log5 = "New record created successfully"
        $log6 = "SERVER_IS_DOWN"
        $dga = "trailers.apple.com."
    condition:
        uint16(0)==0x5a4d and ((10 of ($func*) or any of ($cnc_uri*) or $auth_token or 3 of ($log*)) or ($dga and 4 of them))
}
