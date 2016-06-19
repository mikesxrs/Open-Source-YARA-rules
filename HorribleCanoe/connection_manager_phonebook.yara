rule MSFTConnectionManagerPhonebook {
	strings:
		$cmpbk1 = "cmpbk32.dll"
		$cmpbk2 = "PhoneBookEnumNumbersWithRegionsZero"
		$cmpbk3 = "PhoneBookLoad"
		$cmpbk4 = "PhoneBookUnload"
		$cmpbk5 = "PhoneBookGetCurrentCountryId"
		$cmpbk6 = "PhoneBookGetCountryNameA"
		$cmpbk7 = "PhoneBookFreeFilter"
		$cmpbk8 = "PhoneBookCopyFilter"
		$cmpbk9 = "PhoneBookMatchFilter"
		$cmpbk10 = "PhoneBookGetCountryId"
		$cmpbk11 = "PhoneBookGetPhoneDescA"
		$cmpbk12 = "PhoneBookHasPhoneType"
		$cmpbk13 = "PhoneBookGetRegionNameA"
		$cmpbk14 = "PhoneBookEnumRegions"
		$cmpbk15 = "PhoneBookParseInfoA"
		$cmpbk16 = "PhoneBookGetPhoneDUNA"
		$cmpbk17 = "PhoneBookGetPhoneDispA"
		$cmpbk18 = "PhoneBookGetPhoneCanonicalA"
		$cmpbk19 = "PhoneBookGetPhoneType"
		$cmpbk20 = "PhoneBookEnumNumbers"
		$cmpbk21 = "PhoneBookMergeChanges"
		$cmpbk22 = "PhoneBookGetPhoneNonCanonicalA"

	condition:
		12 of them
}
