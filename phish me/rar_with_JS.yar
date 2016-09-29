/*
  Description: Rar file with a .js inside
  Author: iHeartMalware
  Priority: 5
  Scope: Against Attachment
  Tags: http://phishme.com/rockloader-new-upatre-like-downloader-pushed-dridex-downloads-malwares/
  Created in PhishMe Triage on April 7, 2016 3:41 PM
*/

rule rar_with_js
{
  strings:
  $h1 = "Rar!" 
  $s1 = ".js" nocase
    
  condition:
    $h1 at 0 and $s1
}