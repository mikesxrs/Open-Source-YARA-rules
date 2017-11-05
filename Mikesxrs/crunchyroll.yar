/*
f5ca8d230ca3c71eb0bf96dbec5d9b8aea455486345ccf043329fa85b703fc28/subfile
8d8efbb4c61b9fa771b13f200c4852b40a5e49055d8b9361e82f60cc24569d16/subfile
8b36072a879f957c020792e5381ecb5e4575ebcb94e0b58f9f6c719561614b4a/subfile
2135204a897ec2ccc7a5ad6883e5f7acf0a9e30ac0e9af926c3b93e6c40cb251/subfile
eae53d89d7add187dfe6f4498c99144d7650c37a99792e0e40035d83f73cfb02
*/

rule CrunchyRoll_11/4/17{

meta:
	author = "@X0RC1SM"
	hash = "61ce0980d7b9e7fa352e64b7434a67cebcdd1e7de3dd98651253e28693fbef74"
	hash2 = "eae53d89d7add187dfe6f4498c99144d7650c37a99792e0e40035d83f73cfb02"
	reference = "https://twitter.com/entdark_/status/926778851807637504"

strings:

	$PDB1 = "C:\\Users\\Ben\\Desktop\\taiga-develop\\bin\\Debug\\Taiga.pdb"
	$PDB2 = {43 3A 5C 55 73 65 72 73 5C 42 65 6E 5C 44 65 73 6B 74 6F 70 5C 74 61 69 67 61 2D 64 65 76 65 6C 6F 70 5C 62 69 6E 5C 44 65 62 75 67 5C 54 61 69 67 61 2E 70 64 62}
	$PDB3 = "\\taiga-develop\\bin\\Debug\\Taiga.pdb"
	$PDB4 = "C:\\Users\\Ben\\Desktop\\taiga-develop\\"

condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of ($PDB*)
}
