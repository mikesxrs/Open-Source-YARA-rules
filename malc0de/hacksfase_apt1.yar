rule hacksfase : apt
{
    strings:
        $a = "!@#%$^#@!"
        $b = "Cann't create remote process!"
		$c = "tthacksfas@#$"
    condition:
        filesize < 300KB and (3 of ($a,$b,$c))
}