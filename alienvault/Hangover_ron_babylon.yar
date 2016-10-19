rule Hangover_ron_babylon
{
  meta:
    author = "Alienvault Labs"
    reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"

  strings:
    $a = "Content-Disposition: form-data; name=\"uploaddir\""
    $b1 = "MBVDFRESCT"
    $b2 = "EMSCBVDFRT"
    $b3 = "EMSFRTCBVD"
    $b4= "sendFile"
    $b5 = "BUGMAAL"
    $b6 = "sMAAL"
    $b7 = "SIMPLE"
    $b8 = "SPLIME"
    $b9 = "getkey.php"
    $b10 = "MBVDFRESCT"
    $b11 = "DSMBVCTFRE"
    $b12 = "MBESCVDFRT"
    $b13 = "TCBFRVDEMS"
    $b14 = "DEMOMAKE"
    $b15 = "DEMO"
    $b16 = "UPHTTP"
    

    $c1 = "F39D45E70395ABFB8D8D2BFFC8BBD152"
    $c2 = "90B452BFFF3F395ABDC878D8BEDBD152"
    $c3 = "FFF3F395A90B452BB8BEDC878DDBD152"
    $c4 = "5A9DCB8FFF3F02B8B45BE39D152"
    $c5 = "5A902B8B45BEDCB8FFF3F39D152"
    $c6 = "78DDB5A902BB8FFF3F398B45BEDCD152"
    $c7 = "905ABEB452BFFFBDC878D83F39DBD152"
    $c8 = "D2BFFC8BBD152F3B8D89D45E70395ABF"
    $c9 = "8765F3F395A90B452BB8BEDC878"
    $c10 = "90ABDC878D8BEDBB452BFFF3F395D152"
    $c11 = "F12BDC94490B452AA8AEDC878DCBD187"
    
  condition:
    $a and (1 of ($b*) or 1 of ($c*))
    
}

