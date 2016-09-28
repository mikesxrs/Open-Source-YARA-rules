rule sakula_packed_v2_2
{
    meta:
        description = "Sakula packer v2.2"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m = "goldsunfucker"

    condition:
        all of them
}

