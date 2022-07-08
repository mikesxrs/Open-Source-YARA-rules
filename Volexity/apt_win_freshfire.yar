import "pe"

rule apt_win_freshfire : APT29
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-05-27"
        description = "The FRESHFIRE malware family. The malware acts as a downloader, pulling down an encrypted snippet of code from a remote source, executing it, and deleting it from the remote server."
        reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
        hash = "ad67aaa50fd60d02f1378b4155f69cffa9591eaeb80523489a2355512cc30e8c"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $uniq1 = "UlswcXJJWhtHIHrVqWJJ"
        $uniq2 = "gyibvmt\x00"

        $path1 = "root/time/%d/%s.json"
        $path2 = "C:\\dell.sdr"
        $path3 = "root/data/%d/%s.json" 

    condition:
        (
            pe.number_of_exports == 1 and
            pe.exports("WaitPrompt")
        ) or
        any of ($uniq*) or
        2 of ($path*)
}
