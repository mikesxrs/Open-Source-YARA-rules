rule zhLookUp
{
  meta:
	reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

  strings:
    $s1 = "zhLookUp.Properties"
    
  condition:
    all of them
}