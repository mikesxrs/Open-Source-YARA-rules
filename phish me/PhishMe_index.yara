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

/*
  Description: None
  Priority: 5
  Scope: Against Attachment
  Tags: None
  URL:http://phishme.com/using-yara-to-break-cryptowall-phishing/
  Created in PhishMe's Triage on September 14, 2015 2:35 PM
*/

rule docx_macro
{
  strings:
    $header="PK" 
    $vbaStrings="word/vbaProject.bin" nocase

  condition:
    $header at 0 and $vbaStrings
}


/*
  Description: None
  Priority: 5
  Scope: Against Email
  Tags: None
  URL:http://phishme.com/using-yara-to-break-cryptowall-phishing/
  Created in PhishMe's Triage on September 14, 2015 2:33 PM
*/

rule CryptoWall_Resume_phish
{
  strings:
    $hello2="my name is " nocase
    $file1="resume attached" nocase
    $file2="my resume is pdf file" nocase
    $file3="attached is my resume" nocase
    $sal1="I would appreciate your " nocase
    $sal2="I am looking forward to hearing from you" nocase
    $sal3="I look forward to your reply" nocase
    $sal4="Please message me back" nocase
    $sal5="our early reply will be appreciated" nocase
    $file4="attach is my resume" nocase
    $file5="PDF file is my resume" nocase
    $sal6="Looking forward to see your response" nocase

  condition:
    1 of ($hello*) and 1 of ($file*) and 1 of ($sal*)
}

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

rule PM_docx_with_vba_bin
{
meta:
    author="R.Tokazowski"
    company="PhishMe, Inc."
    URL="http://phishme.com/ms-word-macros-now-social-engineering-malware"

strings:
	$a1 = "PK"
	$a2 = "word/_rels/vbaProject.bin"
	
condition:
	$a1 at 0 and $a2
}

rule PM_Dyre_Delivery : dyre cryptowall crimeware
{
meta:
	author="R.Tokazowski"
	company="PhishMe, Inc."
	URL="http://phishme.com/two-attacks-two-dyres-infrastructure/"

strings:
	$domain1 = "goo.gl" nocase
	$domain2 = "cubby.com" nocase
	$domain3 = "dropbox.com" nocase

	$subject1 = "fax message" nocase
	$subject2 = "new fax" nocase
	$subject3 = "fax report" nocase

	$constant = "Resolution: 400x400 DPI" nocase

condition:

	(1 of ($domain*) and 1 of ($subject*)) or ($constant)

}

rule PM_Dyre_Delivery1 : dyre cryptowall crimeware
{
meta:
    author="R.Tokazowski"
    company="PhishMe, Inc."
    URL="http://phishme.com/dyre-attackers-shift-tactics/"

strings:
    $domain1 = "goo.gl" nocase
    $domain2 = "cubby.com" nocase
    $domain3 = "dropbox.com" nocase
        $php = ".php" nocase

    $subject1 = "fax" nocase
    $subject2 = "message" nocase
        $subject3 = "voice" nocase

    $constant = "Resolution: 400x400 DPI" nocase

        $eh1 = "(EHLO fax-voice.com)"
        $eh2 = "(EHLO voiceservice.com)"
        $eh3 = "(EHLO MyFax.com)"

       $anchor = "EHLO"

condition:

    (1 of ($domain*) and 1 of ($subject*)) or 
        ($constant and 1 of ($domain*)) or 
        (all of ($subject*) and $php) or
        (2 of ($subject*) and $php) or
        any of ($eh*) or
        ($subject1 in (@anchor..@anchor+20)) or
        ($subject3 in (@anchor..@anchor+20))

}

rule PM_Dyre_Voice_Message
{
meta:
	author="R.Tokazowski"
	company="PhishMe, Inc."
	URL="http://phishme.com/two-attacks-two-dyres-infrastructure/"


strings:
	$s1 = "voice message" nocase
	$s2 = "voice redirected message" nocase
	$s3 = "sent: " nocase

condition:
	2 of them
}


rule PM_Zip_With_Exe
{
meta:
	author="R.Tokazowski"
	company="PhishMe, Inc."
	URL="http://phishme.com/two-attacks-two-dyres-infrastructure/"
	
strings:
	$hdr = "PK"
	
	$e1 = ".exe" nocase
	$e2 = ".scr" nocase

	
condition:
	$hdr at 0 and (($e1 in (filesize-100..filesize)) or ($e2 in (filesize-100..filesize)))
}

rule PowerPoint_Embedded_OLE
{
  meta:
    description = "PPSX/PPTX Containers containing embedded data."
    author = "PhishMe"
  strings:
    $magic = {50 4b}
    $meta1 = "ppt/embeddings/oleObject"     
    $meta2 = "ppt/slides/"
  condition:
    $magic at 0 and all of ($meta*)
}

rule PM_outlook_setting_pdf_exe

{
meta:
	author="R.Tokazowski"
	company="PhishMe, Inc."
	URL="http://phishme.com/evolution-upatre-dyre/"

strings:
	$a1 = "PK"
	$a2 = "outlook_setting_pdf.exe"

condition:
	$a1 at 0 and $a2

}
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



rule RockLoader{
	meta:
		name = "RockLoader"
		description = "RockLoader Malware"
		author = "@seanmw"
        
	strings:
		$hdr = {4d 5a 90 00}
		$op1 = {39 45 f0 0f 8e b0 00 00 00}
		$op2 = {32 03 77 73 70 72 69 6e 74 66 41 00 ce 02 53 65}
        
	condition:
		$hdr at 0 and all of ($op*) and filesize < 500KB
}

//invalid hex string at $rttype1
rule PPS_With_OLEObject
{
  meta: 
    description = "PowerPoint Archives with embedded OLE indicators."
    author = "PhishMe"
  strings:
    $magic={d0 cf 11 e0} 
    $stream1="PowerPoint Document" wide
    $stream2="Current User" wide
    $rttype1={0f 00 cc 0f /*[4]*/ } 
    $rttype2={00 00 cd 0f 08 00 00 00 [4] (00|01) (00|01) /*[2]*/} 
    $rttype3={01 00 c3 0f 18 00 00 00 [4] (00|01|02) [7] 00 00 00 00  /*[4]*/} 
  condition:
    $magic at 0 and all of ($stream*)  and all of ($rttype*)
}


   
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

rule viotto_keylogger
{
meta:
  author = "Paul B. (@hexlax) PhishMe Research"
  description = "Matches unpacked Viotto Keylogger samples"
  details "http://phishme.com/viotto-keylogger"

strings:
  $hdr = "MZ"
  $s1 = "Viotto Keylogger"
  $s2 = "msvbvm60"
  $s3 = "FtpPutFileA"
  $s4 = "VBA6"
  $s5 = "SetWindowsHookExA"
condition:
  ($hdr at 0) and all of ($s*)

}
