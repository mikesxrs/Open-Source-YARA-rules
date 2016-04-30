/*
  Description: Rule looking for Russian meta content tags
  Author: iHeartMalware
  Priority: 3
  Scope: Against Email
  Tags: 
  Created in PhishMe Triage on March 11, 2016 3:04 PM
*/

rule criakl_russian_meta_content
{
strings:
  $h1="<meta content=\"ru\"" nocase
condition:
  all of them
}