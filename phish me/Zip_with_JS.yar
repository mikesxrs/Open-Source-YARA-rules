/*
  Description: Hits on ZIP attachments that contain *.js or *.jse - usually JS Dropper malware that has downloaded Kovter & Boaxee in the past.
  Priority: 5
  Scope: Against Attachment
  Tags: FileID
  Author: P.Burbage
  Created in PhishMe's Triage on September 1, 2015 1:43 PM
*/

rule PM_Zip_with_js
{
  strings:
    $hdr="PK" 
    $e1=".js" nocase
    $e2=".jse" nocase

  condition:
    $hdr at 0 and (($e1 in (filesize-100..filesize)) or ($e2 in (filesize-100..filesize)))
}
