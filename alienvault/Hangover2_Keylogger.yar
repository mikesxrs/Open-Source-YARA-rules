
rule Hangover2_Keylogger

{
  meta:
  	author = "Alienvault Labs"
  	referemce = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
  strings:

    $a = "iconfall" wide ascii

    $b = "/c ipconfig /all > "" wide ascii

    $c = "Global\{CHKAJESKRB9-35NA7-94Y436G37KGT}" wide ascii

  condition:

    all of them

}