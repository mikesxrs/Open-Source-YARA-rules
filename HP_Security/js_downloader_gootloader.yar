rule js_downloader_gootloader : downloader
{
  meta:
    description = "JavaScript downloader known to deliver Gootkit or REvil ransomware"
    reference = "https://github.com/hpthreatresearch/tools/blob/main/gootloader/js_downloader_gootloader.yar"
    author = "HP Threat Research @HPSecurity"
    filetype = "JavaScript"
    maltype = "Downloader"
    date = "2021-02-22"

  strings:
    $a = "function"
    $b1 = "while"
    $b2 = "if"
    $b3 = "else"
    $b4 = "return"
    $c = "charAt"
    $d = "substr"
    $e1 = "\".+"
    $e2 = "\\=\\\""
    $e3 = " r,"
    $e4 = "+;\\\""
    $f = /(\w+\[\w+\]\s+=\s+\w+\[\w+\[\w+\]\];)/

  condition:
    #a > 8 and #a > (#b4 + 3) and all of ($b*) and ($c or $d) and any of ($e*) and $f and filesize < 8000
}
