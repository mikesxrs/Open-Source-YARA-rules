rule general_jsp_possible_tiny_fileuploader : General Webshells
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects small .jsp files which have possible file upload utility."
        reference = "https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/"
        date = "2022-06-01"
        hash1 = "4addb9bc9e5e1af8fda63589f6b3fc038ccfd651230fa3fa61814ad080e95a12"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        // read a req parameter of some sort
        $required1 = "request." ascii
        // write a file
        $required2 = "java.io.FileOutputStream" ascii
        $required3 = ".write" ascii

        // do some form of decoding.
        $encoding1 = "java.util.Base64" ascii
        $encoding2 = "crypto.Cipher" ascii
        $encoding3 = ".misc.BASE64Decoder" ascii

    condition:
        (
            filesize < 4KB and
            all of ($required*) and
            any of ($encoding*)
        )
        or
        (
            filesize < 600 and
            all of ($required*)
        )
}

