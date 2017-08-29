rule PNG_dropper:RU TR APT

{

meta:

      author = "CarbonBlack Threat Research"

      date = "2017-June-11"

      description = "Dropper tool that extracts payload from PNG resources"
      
      reference = "https://www.carbonblack.com/2017/08/18/threat-analysis-carbon-black-threat-research-dissects-png-dropper/"

      yara_version = "3.5.0"

      exemplar_hashes = "3a5918c69b6ee801ab8bfc4fc872ac32cc96a47b53c3525723cc27f150e0bfa3, 69389f0d35d003ec3c9506243fd264afefe099d99fcc0e7d977007a12290a290, eeb7784b77d86627bac32e4db20da382cb4643ff8eb86ab1abaebaa56a650158 "

strings:

	$s1 = "GdipGetImageWidth"

	$s2 = "GdipGetImageHeight"

	$s3 = "GdipCreateBitmapFromStream"

	$s4 = "GdipCreateBitmapFromStreamICM"

	$s5 = "GdipBitmapLockBits"

	$s6 = "GdipBitmapUnlockBits"

	$s7 = "LockResource"

	$s8 = "LoadResource"

	$s9 = "ExpandEnvironmentStringsW"

	$s10 = "SetFileTime"

	$s11 = "memcmp"

	$s12 = "strlen"

	$s13 = "memcpy"

	$s14 = "memchr"

	$s15 = "memmove"

	$s16 = "ZwQueryValueKey"

	$s17 = "ZwQueryInformationProcess"

	$s18 = "FindNextFile"

	$s19 = "GetModuleHandle"

	$s20 = "VirtualFree"

	$PNG1 = {89 50 4E 47 [8] 49 48 44 52} //PNG Header

	$bin32_bit1 = {50 68 07 10 06 00 6A 07 8?} //BitmapLockBits_x86

	$bin64_bit1 = {41 B? 07 10 06 00} //BitmapLockBits_x64

	$bin64_bit2 = {41 B? 07 00 00 00}//BitmapLockBits_x64

	$bin32_virt1 = {6A 40 68 00 10 00 00 50 53} //VirtualAlloc_x86

	$bin64_virt1 = {40 41 B? 00 10 00 00}//VirtualAlloc_x64

   

condition:

    uint16(0) == 0x5A4D and // MZ header check

    filesize < 6MB and

    18 of ($s*) and

    (#PNG1 > 7) and

//checks for multiple PNG headers

       ((#bin32_bit1 > 1 and $bin32_virt1) or

//More than 1 of $bin32_bit and $bi32_virt1

       (for 1 of ($bin64_bit*) : (# > 2) and $bin64_virt1))

//1 of $bin64_bit - present more that 2 times and $bin64_Virt1

}
