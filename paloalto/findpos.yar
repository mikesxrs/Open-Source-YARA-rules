import "cuckoo"
 
rule findpos
{
	meta:
		description = "FindPOS is a newly discovered POS family."
		category = "Point of Sale"
		author = "Josh Grunzweig"
 
	strings:
		$s1 = "oprat=2&uid=%I64u&uinfo=%s&win=%d.%d&vers=%s" nocase wide ascii
 
		$pdb1 = "H:\\Work\\Current\\FindStr\\Release\\FindStr.pdb" nocase wide ascii
		$pdb2 = "H:\\Work\\FindStrX\\Release\\FindStr.pdb" nocase wide ascii
    		$pdb3 = "H:\\Work\\Current\\KeyLogger\\Release\\KeyLogger.pdb" nocase wide ascii
 
	condition:
		any of ($s*) or
		any of ($pdb*) or
        (
          cuckoo.sync.mutex(/WIN_[a-fA-F0-9]{16}/) and
          cuckoo.registry.key_access(/\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/) and
          (
              cuckoo.filesystem.file_access(/C\:\\WINDOWS\\System32\\\w{8}\.exe/) or
              cuckoo.filesystem.file_access(/C\:\\Documents\ and\ Settings\\[^\\]+\\\w{8}\.exe/)
          )
        )
}