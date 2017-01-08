rule glassrat
{
	strings:
    	$a = "PostQuitMessage"
        $b = "pwlfnn10,gzg"
        $c = "update.dll"
        $d = "_winver"
    condition:
    	all of them

}