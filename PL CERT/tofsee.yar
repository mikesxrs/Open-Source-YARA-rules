rule tofsee
{
    meta:
      author="akrasuski1"
	    reference = "https://www.cert.pl/en/news/single/tofsee-en/"
	strings:

	$decryptStr = {32 55 14	88 10 8A D1 02 55 18 F6 D9 00 55 14}
	$xorGreet = {C1 EB 03 C0 E1 05 0A D9 32 DA 34 C6 88 1E}
	$xorCrypt = {F7 FB 8A 44 0A 04 30 06 FF 41 0C}

	$string_res1 = "loader_id"
	$string_res2 = "born_date"
	$string_res3 = "work_srv"
	$string_res4 = "flags_upd"
	$string_res5 = "lid_file_upd"
	$string_res6 = "localcfg"

	$string_var0 = "%RND_NUM"
	$string_var1 = "%SYS_JR"
	$string_var2 = "%SYS_N"
	$string_var3 = "%SYS_RN"
	$string_var4 = "%RND_SPACE"
	$string_var5 = "%RND_DIGIT"
	$string_var6 = "%RND_HEX"
	$string_var7 = "%RND_hex"
	$string_var8 = "%RND_char"
	$string_var9 = "%RND_CHAR"

    condition:
		(7 of ($string_var*) and 4 of ($string_res*))
		or
		(7 of ($string_var*) and 2 of ($decryptStr, $xorGreet, $xorCrypt))
		or
	
