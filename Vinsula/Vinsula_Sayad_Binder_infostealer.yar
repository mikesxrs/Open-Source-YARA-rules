rule Vinsula_Sayad_Binder : infostealer
{
	meta: 
		copyright = "Vinsula, Inc" 
		description = "Sayad Infostealer Binder" 
		version = "1.0" 
		actor = "Sayad Binder" 
		in_the_wild = true 
		reference = "http://vinsula.com/2014/07/20/sayad-flying-kitten-infostealer-malware/"

    strings: 
		$pdbstr = "\\Projects\\C#\\Sayad\\Source\\Binder\\obj\\Debug\\Binder.pdb" 
		$delphinativestr = "DelphiNative.dll" nocase
		$sqlite3str = "sqlite3.dll" nocase
		$winexecstr = "WinExec" 
		$sayadconfig = "base.dll" wide

     condition:
        all of them
}