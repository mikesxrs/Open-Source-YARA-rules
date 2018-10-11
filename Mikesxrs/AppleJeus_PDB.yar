rule AppleJeus_PDB
{
  meta:
    author = "mikesxrs"
    description = "PDB Path in  malware"
    reference = "https://securelist.com/operation-applejeus/87553/"

  strings: 
	$pdb1 = "Z:\\jeus\\downloader\\downloader_exe_vs2010\\Release\\dloader.pdb"
    $pdb2 = "Z:\\jeus\\downloader\\"
    $pdb3 = "H:\\DEV\\TManager\\all_BOSS_troy\\T_4.2\\T_4.2\\Server_\\x64\\Release\\ServerDll.pdb"
    $pdb4 = "H:\\DEV\\TManager\\DLoader\\20180702\\dloader\\WorkingDir\\Output\\00000009\\Release\\dloader.pdb"
    $pdb5 = "H:\\DEV\\TManager\\DLoader\\20180702\\dloader\\WorkingDir\\Output\\00000006\\Release\\dloader.pdb"
    $pdb6 = "H:\\DEV\\TManager\\"
  
  condition:
    any of them

}
