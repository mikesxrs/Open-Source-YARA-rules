rule TropicTrooper_keyboy_PDB
{
  meta:
    author = "mikesxrs"
    description = "PDB Path in  malware"
    reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
    reference2 = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/research/the-keyboys-are-back-in-town.html"

  strings:
	$pdb1 = "D:\\Work\\Project\\VS\\house\\Apple\\Apple_20180115\\Release\\InstallClient.pdb"
	$pdb2 = "D:\\Work\\Project\\VS\\house\\Apple\\Apple_20180115\\Release\\FakeRun.pdb"
	$pdb3 = "D:\\Work\\Project\\VS\\HSSL\\HSSL_Unicode _2\\Release\\ServiceClient.pdb"
	$pdb4 = "D:\\Work\\VS\\Horse\\TSSL\\TSSL_v3.0\\TClient\\Release\\TClient.pdb"
	$pdb5 = "D:\\Work\\VS\\Horse\\TSSL\\TSSL_v0.3.1_20170722\\TClient\\x64\\Release\\TClient.pdb"
	$pdb6 = "D:\\Work\\VS\\Horse\\TSSL\\TSSL_v0.3.1_20170722\\TClient\\Release\\TClient.pdb"
	$pdb7 = "D:\\work\\vs\\UsbFerry_v2\\bin\\UsbFerry.pdb"
	$pdb8 = "E:\\Work\\VS Project\\cyassl-3.3.0\\out\\SSLClient_x64.pdb"
//hunting rule    
    $pdb9 = "D:\\Work\\Project\\VS\\house\\"
    $pdb10 = "D:\\Work\\VS\\Horse\\"
    $pdb11 = "D:\\work\\vs\\"
    $pdb12 = "E:\\Work\\VS Project\\"
    $pdb13 = "\\Release\\InstallClient.pdb"
    $pdb14 = "\\Release\\FakeRun.pdb"
    $pdb15 = "\\Release\\ServiceClient.pdb"
    $pdb16 = "\\Release\\TClient.pdb"
    $pdb17 = "\\bin\\UsbFerry.pdb"
    $pdb18 = "\\out\\SSLClient_x64.pdb"


  condition:
    any of them

}
