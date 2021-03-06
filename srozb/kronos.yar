/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2016-11-14
	Identifier: 
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_0056246214368c7c7d6181727fdab487 {
	meta:
		description = "Auto-generated rule - file 0056246214368c7c7d6181727fdab487"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "4322880fee6fbc5d54583027e34cb99713147d87b4ff27c1d0e5bcd71c078156"
	strings:
		$s1 = "Resonated.exe" fullword wide /* score: '22.00' */
		$s2 = "tAHpvfWFh" fullword ascii /* base64 encoded string ' zo}aa' */ /* score: '14.00' */
		$s3 = "3-V:\\`" fullword ascii /* score: '11.00' */
		$s4 = "wxANdsvRQVY.Properties.Resources.resources" fullword ascii /* score: '11.00' */
		$s5 = "get_lotqcrsyhUXr" fullword ascii /* score: '10.01' */
		$s6 = "wxANdsvRQVY.Properties.Resources" fullword wide /* score: '10.00' */
		$s7 = "ListViewVirtualItemsSelectionRangeChangedEventHandler" fullword ascii /* score: '9.00' */
		$s8 = "DebuggerTypeProxyAttribute" fullword ascii /* score: '9.00' */
		$s9 = "ListViewVirtualItemsSelectionRangeChangedEventArgs" fullword ascii /* score: '9.00' */
		$s10 = "iRcKifmjuub" fullword ascii /* score: '9.00' */
		$s11 = "MRkget" fullword ascii /* score: '8.00' */
		$s12 = "8.9.6.3" fullword wide /* score: '8.00' */
		$s13 = "4.1.2.9" fullword wide /* score: '8.00' */
		$s14 = "wxANdsvRQVY.Resources" fullword ascii /* score: '8.00' */
		$s15 = "wxANdsvRQVY.Properties" fullword ascii /* score: '8.00' */
		$s16 = "nvxugd" fullword ascii /* score: '7.00' */
		$s17 = "fedapl" fullword ascii /* score: '7.00' */
		$s18 = "tKKORunuy" fullword ascii /* score: '7.00' */
		$s19 = "nhukomi" fullword ascii /* score: '7.00' */
		$s20 = "xuwvhp" fullword ascii /* score: '7.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and ( 10 of ($s*) ) ) or ( all of them )
}

rule b02ecc516834373f753b4a56428780f1 {
	meta:
		description = "Auto-generated rule - file b02ecc516834373f753b4a56428780f1"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "c3b3fcc4d911d24473bf0a1b42e93de250b4ecf1b74632158a54c68013403613"
	strings:
		$s1 = "ProcessHostFactoryHelper" fullword ascii /* score: '22.00' */
		$s2 = "Astray.exe" fullword wide /* score: '22.00' */
		$s3 = "System.Web.Profile" fullword ascii /* score: '14.00' */
		$s4 = "X509KeyUsageExtension" fullword ascii /* score: '13.00' */
		$s5 = "DrawListViewColumnHeaderEventArgs" fullword ascii /* score: '12.00' */
		$s6 = "Ascriptions Cheapest Inc Colleague Economised" fullword wide /* score: '11.00' */
		$s7 = "-Ascriptions Cheapest Inc Colleague Economised" fullword ascii /* score: '11.00' */
		$s8 = "jPuZOXwFDv.Properties.Resources.resources" fullword ascii /* score: '11.00' */
		$s9 = "System.IO.Ports" fullword ascii /* score: '10.00' */
		$s10 = "ShowSaveAsDialog" fullword ascii /* score: '10.00' */
		$s11 = "HostingEnvironment" fullword ascii /* score: '10.00' */
		$s12 = "DataGridViewComboBoxEditingControl" fullword ascii /* score: '10.00' */
		$s13 = "get_jOMloqc" fullword ascii /* score: '9.01' */
		$s14 = "jPuZOXwFDv.Properties.Resources" fullword wide /* score: '9.00' */
		$s15 = "8.7.9.5" fullword wide /* score: '8.00' */
		$s16 = "IPAddressCollection" fullword ascii /* score: '8.00' */
		$s17 = "tgmFGETJ" fullword ascii /* score: '8.00' */
		$s18 = "6.1.4.2" fullword wide /* score: '8.00' */
		$s19 = "Competitive Containable" fullword wide /* score: '8.00' */
		$s20 = "jPuZOXwFDv.Properties" fullword ascii /* score: '8.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 800KB and ( 10 of ($s*) ) ) or ( all of them )
}

rule sig_2edb9e91d43f669148c004e0faed8c3a {
	meta:
		description = "Auto-generated rule - file 2edb9e91d43f669148c004e0faed8c3a"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "0e15715b82f4d59a376c9e5e5842d43fae01fdf4408e3453a4b1771bb80c9159"
	strings:
		$s1 = "Toe.exe" fullword wide /* score: '21.00' */
		$s2 = "System.Web.UI.WebControls.WebParts" fullword ascii /* score: '16.00' */
		$s3 = "Selenology Protactinium Slapper" fullword wide /* score: '11.00' */
		$s4 = "x:\\kEZ" fullword ascii /* score: '11.00' */
		$s5 = "uJGRaoEzf.Properties.Resources.resources" fullword ascii /* score: '11.00' */
		$s6 = "get_IcfXzSYMdZCj" fullword ascii /* score: '10.01' */
		$s7 = "uJGRaoEzf.Properties.Resources" fullword wide /* score: '9.00' */
		$s8 = "iFhosTkhl" fullword ascii /* score: '9.00' */
		$s9 = "AsyncCompletedEventHandler" fullword ascii /* score: '9.00' */
		$s10 = "Tonsillitis Prevalence Inc Sextants Recliner" fullword wide /* score: '8.00' */
		$s11 = ",Tonsillitis Prevalence Inc Sextants Recliner" fullword ascii /* score: '8.00' */
		$s12 = "uJGRaoEzf.Properties" fullword ascii /* score: '8.00' */
		$s13 = "1.6.6.4" fullword wide /* score: '8.00' */
		$s14 = "Selenology Protactinium Slapper" fullword ascii /* score: '8.00' */
		$s15 = "5.1.8.9" fullword wide /* score: '8.00' */
		$s16 = "uJGRaoEzf.Resources" fullword ascii /* score: '8.00' */
		$s17 = "lfzotn" fullword ascii /* score: '7.00' */
		$s18 = "MemoryFailPoint" fullword ascii /* score: '7.00' */
		$s19 = "EncoderFallbackException" fullword ascii /* score: '6.00' */
		$s20 = "HasCopySemanticsAttribute" fullword ascii /* score: '6.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and ( 10 of ($s*) ) ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

