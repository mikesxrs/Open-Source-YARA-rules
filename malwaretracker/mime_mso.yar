rule openxml_remote_content
{
 meta:
  ref = "https://www.defcon.org/html/defcon-22/dc-22-speakers.html#Crenshaw"
  author = "MalwareTracker.com @mwtracker"
  date = "Aug 10 2014"
  hash = "63ea878a48a7b0459f2e69c46f88f9ef"

  strings:
  $a = "schemas.openxmlformats.org" ascii nocase
  $b = "TargetMode=\"External\"" ascii nocase

  condition:
  all of them
}

rule theme_MH370 {
    meta:
	author = "MalwareTracker.com @mwtracker"
	reference = "http://blog.malwaretracker.com/2014/04/cve-2012-0158-in-mime-html-mso-format.html"
        version = "1.0"
        date = "2014-04-09"
    strings:
        $callsign1 = "MH370" ascii wide nocase fullword
        $callsign2 = "MAS370" ascii wide nocase fullword
        $desc1 = "Flight 370" ascii wide nocase fullword
    condition:
        any of them
}

rule doc_zws_flash {
    meta:
    ref ="2192f9b0209b7e7aa6d32a075e53126d"
    author = "MalwareTracker.com @mwtracker"
    date = "2013-01-11"

    strings:
        $header = {66 55 66 55 ?? ?? ?? 00 5A 57 53}
        $control = "CONTROL ShockwaveFlash.ShockwaveFlash"

    condition:
        all of them
}

rule apt_actor_tran_duy_linh
{
       meta:
		author = "MalwareTracker.com @mwtracker"
         	info = "OLE author"
       strings:
      		$auth = { 4E 6F 72 6D 61 6C 2E 64 6F 74 6D 00 1E 00 00 00 10 00 00 00 54 72 61 6E 20 44 75 79 20 4C 69 6E 68 }

       condition:
               	$auth
}

rule mime_mso
{
meta:
    comment = "mime mso detection"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    author = "@mwtracker"
strings:
	$a="application/x-mso"
	$b="MIME-Version"
	$c="ocxstg001.mso"
	$d="?mso-application"
condition:
	$a and $b or $c or $d
}


rule mime_mso_embedded_SuppData
{
meta:
    comment = "mime mso office obfuscation"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    hash = "77739ab6c20e9dfbeffa3e2e6960e156"
    author = "@mwtracker"
    date = "Mar 5 2015"

strings:
    $a = "docSuppData"
    $b = "binData"
    $c = "schemas.microsoft.com"

condition:
    all of them
}


rule mime_mso_embedded_ole
{
meta:
    comment = "mime mso office obfuscation"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    hash = "77739ab6c20e9dfbeffa3e2e6960e156"
    author = "@mwtracker"
    date = "Mar 5 2015"

strings:
    $a = "docOleData"
    $b = "binData"
    $c = "schemas.microsoft.com"

condition:
    all of them
}

rule mime_mso_vba_macros
{
meta:
    comment = "mime mso office obfuscation"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    hash = "77739ab6c20e9dfbeffa3e2e6960e156"
    author = "malwaretracker.com @mwtracker"
    date = "Mar 5 2015"

strings:
    $a = "macrosPresent=\"yes\""
    $b = "schemas.microsoft.com"

condition:
    all of them
}
