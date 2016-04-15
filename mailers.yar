/*
  Description: This rule keys on email headers that may have been sent from a malicious PHP script on a compromised webserver.
  Priority: 4
  Scope: Against Email
  Tags: None
  Author: P.Burbage
  Created in PhishMe's Triage on September 1, 2015 1:43 PM
*/

rule PM_Email_Sent_By_PHP_Script
{
  strings:
    $php1="X-PHP-Script" fullword
    $php2="X-PHP-Originating-Script" fullword
    $php3="/usr/bin/php" fullword

  condition:
    any of them
}