rule maldoc_cve_2012_0158 : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect MSComctlLib.ListViewCtrl.2 in DOC documents - cve_2012_0158"

	strings:
		//MSComctlLib.ListViewCtrl.2 GUID={BDD1F04B-858B-11D1-B16A-00C0F0283628}
	        $doc_activex_01 = { 4B F0 D1 BD 8B 85 D1 11 B1 6A 00 C0 F0 28 36 28 }

	condition:
                // DOC/Composite file magic
		uint32be(0) == 0xd0cf11e0 and uint32be(4) == 0xa1b11ae1
		and $doc_activex_01
}



rule maldoc_moniker_cve_2017_0199 : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized DOC documents it to URL Moniker HTA handling CVS-2017-0199"

	strings:
                //GUID of URL Moniker =  79EAC9E0-BAF9-11CE-8C82-00AA004BA90B
                $doc_moniker_01 = { E0 C9 EA 79 f9 BA CE 11 8C 82 00 AA 00 4B A9 0B }

		//IID_IMoniker is defined as 0000000f-0000-0000-C000-000000000046
                // too poor for detection

	condition:
                // DOC/Composite file magic
		uint32be(0) == 0xd0cf11e0 and uint32be(4) == 0xa1b11ae1
                and $doc_moniker_01
}
