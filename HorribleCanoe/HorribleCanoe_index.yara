rule compiled_autoit {
	strings:
		$str1 = "This is a compiled AutoIt script. AV researchers please email avsupport@autoitscript.com for support."

	condition:
		all of them
}

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
rule delphi_wlan {
	strings:
		$dll = "wlanapi.dll"

		$api2 = "WlanOpenHandle"
		$api3 = "WlanCloseHandle"
		$api4 = "WlanEnumInterfaces"
		$api5 = "WlanQueryInterface"
		$api6 = "WlanGetAvailableNetworkList"

		$options1 = "80211_OPEN"
		$options2 = "80211_SHARED_KEY"
		$options3 = "WPA_PSK"
		$options4 = "WPA_NONE"
		$options5 = "RSNA"
		$options6 = "RSNA_PSK"
		$options7 = "IHV_START"
		$options8 = "IHV_END"
		$options9 = "WEP104"
		$options10 = "WPA_USE_GROUP OR RSN_USE_GROUP"
		$options11 = "IHV_START"
		$options12 = "IHV_END"
		$options13 = "WEP40"

	condition:
		$dll and 3 of ($api*) and 6 of ($options*)
}


rule ejects_cdrom {
	strings:
		$cddoor1 = "mciSendString"
		$cddoor2 = "set cdaudio door open"
		$cddoor3 = "set cdaudio door closed"

	condition:
		2 of them
}

rule lowers_security {
	strings:
		$actions1 = "EnableLUA"
		$actions2 = "AntiVirusDisableNotify"
		$actions3 = "DisableNotifications"
		$actions4 = "UpdatesDisableNotify"

	condition:
		2 of them
}



rule reads_clipboard {
	strings:
		$clipboard1 = "CloseClipboard"
		$clipboard2 = "EmptyClipboard"
		$clipboard3 = "EnumClipboardFormats"
		$clipboard4 = "GetClipboardData"
		$clipboard5 = "IsClipboardFormatAvailable"
		$clipboard6 = "OpenClipboard"
		$clipboard7 = "RefreshClipboard"
		$clipboard8 = "RegisterClipboardFormat"
		$clipboard9 = "SendYourClipboard"
		$clipboard10 = "SetClipboardData"

	condition:
		5 of them
}

rule pcre {
	strings:
		$pcre1 = "this version of PCRE is not compiled with PCRE_UTF8 support"
		$pcre2 = "this version of PCRE is not compiled with PCRE_UCP support"
		$pcre3 = "alpha"
		$pcre4 = "lower"
		$pcre5 = "upper"
		$pcre6 = "alnum"
		$pcre7 = "ascii"
		$pcre8 = "blank"
		$pcre9 = "cntrl"
		$pcre10 = "digit"
		$pcre11 = "graph"
		$pcre12 = "print"
		$pcre13 = "punct"
		$pcre14 = "space"
		$pcre15 = "word"
		$pcre16 = "xdigit"
		$pcre17 = "at end of pattern"
		$pcre18 = "numbers out of order in {} quantifier"
		$pcre19 = "number too big in {} quantifier"
		$pcre20 = "missing terminating ] for character class"
		$pcre21 = "invalid escape sequence in character class"
		$pcre22 = "range out of order in character class"
		$pcre23 = "nothing to repeat"
		$pcre24 = "operand of unlimited repeat could match the empty string"
		$pcre25 = "internal error: unexpected repeat"
		$pcre26 = "unrecognized character after (? or (?-"
		$pcre27 = "POSIX named classes are supported only within a class"
		$pcre28 = "missing )"
		$pcre29 = "reference to non-existent subpattern"
		$pcre30 = "erroffset passed as NULL"
		$pcre31 = "unknown option bit(s) set"
		$pcre32 = "missing ) after comment"
		$pcre33 = "parentheses nested too deeply"
		$pcre34 = "regular expression is too large"
		$pcre35 = "failed to get memory"
		$pcre36 = "unmatched parentheses"
		$pcre37 = "internal error: code overflow"
		$pcre38 = "unrecognized character after (?<"
		$pcre39 = "lookbehind assertion is not fixed length"
		$pcre40 = "malformed number or name after (?("
		$pcre41 = "conditional group contains more than two branches"
		$pcre42 = "assertion expected after (?("
		$pcre43 = "(?R or (?[+-]digits must be followed by )"
		$pcre44 = "unknown POSIX class name"
		$pcre45 = "POSIX collating elements are not supported"
		$pcre46 = "this version of PCRE is not compiled with PCRE_UTF8 support"
		$pcre47 = "spare error"
		$pcre48 = "character value in x{...} sequence is too large"
		$pcre49 = "invalid condition (?(0)"
		$pcre50 = "number after (?C is > 255"
		$pcre51 = "closing ) for (?C expected"
		$pcre52 = "recursive call could loop indefinitely"
		$pcre53 = "unrecognized character after (?P"
		$pcre54 = "syntax error in subpattern name (missing terminator)"
		$pcre55 = "two named subpatterns have the same name"
		$pcre56 = "invalid UTF-8 string"
		$pcre57 = "subpattern name is too long (maximum 32 characters)"
		$pcre58 = "too many named subpatterns (maximum 10000)"
		$pcre59 = "repeated subpattern is too long"
		$pcre60 = "octal value is greater than 377 (not in UTF-8 mode)"
		$pcre61 = "internal error: overran compiling workspace"
		$pcre62 = "internal error: previously-checked referenced subpattern not found"
		$pcre63 = "DEFINE group contains more than one branch"
		$pcre64 = "repeating a DEFINE group is not allowed"
		$pcre65 = "inconsistent NEWLINE options"
		$pcre66 = "different names for subpatterns of the same number are not allowed"
		$pcre67 = "subpattern name expected"
		$pcre68 = "a numbered reference must not be zero"

	condition:
		30 of them
}