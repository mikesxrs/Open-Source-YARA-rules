rule TEMP_Periscope_July2018_Spearphish : email {
meta:
  Author = "Insikt Group, Recorded Future"
  TLP = "White"
  Date = "2018-09-22"
  Description ="Rule to identify spearphish sent by Chinese threat actor TEMP.Periscope during July 2018 campaign” 
strings:
  $eml_1="From:"
  $eml_2="To:"
  $eml_3="Subject:"
  $greeting_1="Dear,"
  $content_1="Melissa Coade" nocase
  $content_2="Below is the Report Website and conatc"
  $content_3="Would yo mind giving me"
  $url_1="file://"
  $url_2="https://drive.google.com/open?"
condition:
  all of ($eml*) and all of ($greeting*) and 2 of ($content*) and 2 of ($url*) 
}
