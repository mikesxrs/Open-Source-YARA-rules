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