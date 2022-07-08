rule trojan_golang_pantegana : Commodity
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects PANTEGANA, a Golang backdoor used by a range of threat actors due to its public availability."
        date = "2022-03-30"
        hash1 = "8297c99391aae918f154077c61ea94a99c7a339166e7981d9912b7fdc2e0d4f0"
        reference = "https://github.com/elleven11/pantegana"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 1

    strings:
        $s1 = "RunFingerprinter" ascii
        $s2 = "SendSysInfo" ascii
        $s3 = "ExecAndGetOutput" ascii
        $s4 = "RequestCommand" ascii
        $s5 = "bindataRead" ascii
        $s6 = "RunClient" ascii
        
        $magic = "github.com/elleven11/pantegana" ascii

    condition:
        5 of ($s*) or 
        $magic
}

