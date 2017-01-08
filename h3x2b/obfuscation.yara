rule obfuscation_singlebyte_mov : feature obfuscation
{
        meta:
                author = "Andreas Schuster"
                description = "Detects strings obfuscated by single-byte mov ex: mov [ebp+String+1], A"
                //Check also:
                //https://insights.sei.cmu.edu/sei_blog/2012/11/writing-effective-yara-signatures-to-identify-malware.html

        strings:
		$singleb_mov = { c6 45 [2] c6 45 [2] c6 45 [2] c6 45}

        condition:
                //Contains all of the strings
                all of them
}
