rule Lightserver_variant_B : Red_Salamander

{

      meta:

            description = "Elise lightserver variant."

            author = "PwC Cyber Threat Operations :: @michael_yip"

            version = "1.0"

            created = "2015-12-16"

            exemplar_md5 = "c205fc5ab1c722bbe66a4cb6aff41190"

            reference = "http://pwc.blogs.com/cyber_security_updates/2015/12/elise-security-through-obesity.html"


      strings:

            $json = /\{\"r\":\"[0-9]{12}\",\"l\":\"[0-9]{12}\",\"u\":\"[0-9]{7}\",\"m\":\"[0-9]{12}\"\}/

            $mutant1 = "Global\\{7BDACDEE-8BF6-4664-B946-D00FCFF1FFBA}"

            $mutant2 = "{5947BACD-63BF-4e73-95D7-0C8A98AB95F2}"

            $serv1 = "Server1=%s"

            $serv2 = "Server2=%s"

            $serv3 = "Server3=%s"

      condition:

            uint16(0) == 0x5A4D and ($json or $mutant1 or $mutant2 or all of ($serv*))

}
