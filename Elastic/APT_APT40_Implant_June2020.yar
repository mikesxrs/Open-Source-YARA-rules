rule APT_APT40_Implant_June2020 {
   meta:
       version = "1.0"
       author =  "Elastic Security"
       date_added = "2020-06-19"
       description = "APT40 second stage implant"
       reference = "https://www.elastic.co/security-labs/advanced-techniques-used-in-malaysian-focused-apt-campaign"
    strings:
        $a = "/list_direction" fullword wide
        $b = "/post_document" fullword wide
        $c = "/postlogin" fullword wide
        $d = "Download Read Path Failed %s" fullword ascii
        $e = "Open Pipe Failed %s" fullword ascii
        $f = "Open Remote File %s Failed For: %s" fullword ascii
        $g = "Download Read Path Failed %s" fullword ascii
        $h = "\\cmd.exe" fullword wide
    condition:
        all of them
}
