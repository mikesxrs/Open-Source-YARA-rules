rule APT_DeputyDog_Strings
{

	meta:

		author = "FireEye Labs"
		version = "1.0"
		description = "detects string seen in samples used in 2013-3893 0day attacks"
		reference = "8aba4b5184072f2a50cbc5ecfe326701"

	strings:

		$mz = {4d 5a}
		$a = "DGGYDSYRL"

	condition:

		($mz at 0) and $a

}

rule callTogether_certificate
{

  meta:

    author = "Fireeye Labs"

    version = "1.0"

    reference_hash = "d08e038d318b94764d199d7a85047637"

    reference = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

    description = "detects binaries signed with the CallTogether certificate"

  strings:

    $serial = {452156C3B3FB0176365BDB5B7715BC4C}

    $o = "CallTogether, Inc."

  condition:

    $serial and $o

}

rule FE_APT_9002_rat

{

	meta:
		author = "FireEye Labs"
		reference = "https://www.fireeye.com/blog/threat-research/2013/11/operation-ephemeral-hydra-ie-zero-day-linked-to-deputydog-uses-diskless-method.html"

    strings:

        $mz = {4d 5a}

        $a = "rat_UnInstall" wide ascii

    condition:

        ($mz at 0) and $a

}

rule MACROCHECK
{
    meta:
        description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
        author = "Fireeye Labs"
        version = "1.0"
 
    strings:
        $PARAMpword = "pword=" ascii wide
        $PARAMmsg = "msg=" ascii wide
        $PARAMuname = "uname=" ascii
        $userform = "UserForm" ascii wide
        $userloginform = "UserLoginForm" ascii wide
        $invalid = "Invalid username or password" ascii wide
        $up1 = "uploadPOST" ascii wide
        $up2 = "postUpload" ascii wide
        
    condition:
        all of ($PARAM*) or (($invalid or $userloginform or $userform) and ($up1 or $up2))
}


rule Molerats_certs

{

	meta:

		author = "FireEye Labs"

		description = "this rule detections code signed with certificates used by the Molerats actor"
        
        reference = "https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html"

strings:

	$cert1 = {06 50 11 A5 BC BF 83 C0 93 28 16 5E 7E 85 27 75}
    $cert2 = {03 e1 e1 aa a5 bc a1 9f ba 8c 42 05 8b 4a bf 28}
    $cert3 = {0c c0 35 9c 9c 3c da 00 d7 e9 da 2d c6 ba 7b 6d}



condition:

1 of ($cert*)

}

rule qti_certificate

{

    meta:

        author = "Fireeye Labs"

        reference_hash = "cfa3e3471430a0096a4e7ea2e3da6195"

        reference = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

        description = "detects binaries signed with the QTI International Inc certificate"   

    strings:

        $cn = "QTI International Inc"

        $serial = { 2e df b9 fd cf a0 0c cb 5a b0 09 ee 3a db 97 b9 }

    condition:

        $cn and $serial

}