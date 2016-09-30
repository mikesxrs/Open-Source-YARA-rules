rule MirageAPTBackdoorSample
{
        meta:
			Description  = "Backdoor.Mirage.sm"
			ThreatLevel  = "5"

        strings:
               $a1 = "welcome to the desert of the real" ascii wide
               $a2 = "Mirage" ascii wide
               $b = "Encoding: gzip" ascii wide
               $c = /\/[A-Za-z]*\?hl=en/
        condition:
               (($a1 or $a2) or $b) and $c
}