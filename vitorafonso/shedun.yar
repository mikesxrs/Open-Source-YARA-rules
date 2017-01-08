rule shedun
{
	meta:
		description = "Detects libcrypt_sign used by shedun"
		author = "vitorafonso"
		sample = "919f1096bb591c84b4aaf964f0374765c3fccda355c2686751219926f2d50fab"

	strings:
		$a = "madana!!!!!!!!!"
		$b = "ooooop!!!!!!!!!!!"
		$c = "hehe you never know what happened!!!!"

	condition:
		all of them

}
