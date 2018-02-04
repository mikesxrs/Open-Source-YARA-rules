rule W97M_Vawtrak_dropper
{
meta:
author="McAfee"
description="W97M_Vawtrak_Dropper"
reference = "https://securingtomorrow.mcafee.com/mcafee-labs/w97m-downloader-serving-vawtrak/"

strings:
$asterismal="asterismal"
$bootlicking="bootlicking"
$shell="WScript.Shell"
$temp="%temp%"
$oxygon="oxygon.exe"
$saxhorn = "saxhorn"
$fire = "Fire"
$bin= "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e"

condition:
all of them
}
