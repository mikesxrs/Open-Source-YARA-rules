rule InceptionVBS {

    meta:
		author = "Blue Coat Systems, Inc"
		info = "Used by unknown APT actors: Inception"
		reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    
    strings:
		$a = "c = Crypt(c,k)"
		$b = "fso.BuildPath( WshShell.ExpandEnvironmentStrings(a), nn)"
        
    condition:
		all of them
}
