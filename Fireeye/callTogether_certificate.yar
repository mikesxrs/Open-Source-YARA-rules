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