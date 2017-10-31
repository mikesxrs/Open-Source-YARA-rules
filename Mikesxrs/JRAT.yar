rule JRAT
{
	meta:
    	  Author = "@X0RC1SM"
        Description = "Looking for unique PDB"
        Reference = "https://repo.cryptam.com/nodes/03e36f49d38082bcac91716747f7827286fbebee62d412fb39a45b4ec7a082f5.txt"
        Date = "2017-04-05"
    strings:
	      $JRAT1 = "/Jrat.classPK" ascii wide nocase
        $JRAT2 = "/JRat.class" ascii wide nocase
		    $JRAT3 = "META-INF/MANIFEST.MF" ascii wide nocase
	condition:
		all of them
}
