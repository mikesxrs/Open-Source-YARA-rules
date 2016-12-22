rule Adwind_JAR_PACKA {
 meta:
 author = “Vitaly Kamluk, Vitaly.Kamluk@kaspersky.com”
 last_modified = “2015-11-30”
 reference = "https://securelist.com/securelist/files/2016/02/KL_AdwindPublicReport_2016.pdf"
 strings:
 $b1 = “.class” ascii
 $b2 = “c/a/a/” ascii
 $b3 = “b/a/” ascii
 $b4 = “a.dat” ascii
 $b5 = “META-INF/MANIFEST.MF” ascii
 condition:
 int16(0) == 0x4B50 and ($b1 and $b2 and $b3 and $b4 and $b5)
}
rule Adwind_JAR_PACKB {
 meta:
 author = “Vitaly Kamluk, Vitaly.Kamluk@kaspersky.com”
 last_modified = “2015-11-30”
 reference = "https://securelist.com/securelist/files/2016/02/KL_AdwindPublicReport_2016.pdf"
 strings:
 $c1 = “META-INF/MANIFEST.MF” ascii
 $c2 = “main/Start.class” ascii
 $a1 = “config/config.perl” ascii
 $b1 = “java/textito.isn” ascii
 condition:
 int16(0) == 0x4B50 and ($c1 and $c2 and ($a1 or $b1))
}
