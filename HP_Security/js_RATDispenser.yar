rule js_RATDispenser : downloader
{
  meta:
    description = "JavaScript downloader resp. dropper delivering various RATs"
    reference = "https://threatresearch.ext.hp.com/javascript-malware-dispensing-rats-into-the-wild/"
    author = "HP Threat Research @HPSecurity"
    filetype = "JavaScript"
    maltype = "Downloader"
    date = "2021-05-27" 

  strings:
    $a = /{(\d)}/

    $c1 = "/{(\\d+)}/g"
    $c2 = "eval"
    $c3 = "prototype"

    $d1 = "\\x61\\x64\\x6F\\x64\\x62\\x2E"
    $d2 = "\\x43\\x68\\x61\\x72\\x53\\x65\\x74"
    $d3 = "\\x54\\x79\\x70\\x65"

    $e1 = "adodb."
    $e2 = "CharSet"
    $e3 = "Type"

    $f1 = "arguments"
    $f2 = "this.replace"

  condition:
    #a > 50 and all of ($c*) and (any of ($d*) or any of ($e*)) and all of ($f*) and filesize < 2MB
}
