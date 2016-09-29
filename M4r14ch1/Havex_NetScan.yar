rule Havex_NetScan_Malware {
meta:
        description = "This rule will search for known indicators of a Havex Network Scan module infection. This module looks for hosts listening on known ICS-related ports to identify OPC or ICS systems and the file created when the scanning data is written."
        author = "M4r14ch1"
        reference = "https://github.com/M4r14ch1/Havex-Network-Scanner-Modules"
        date = "2015/12/21"
        strings:
                $s0 = "~tracedscn.yls" wide nocase //yls file created in temp directory
                $s1 = { 2B E2 ?? }      //Measuresoft ScadaPro
                $s2 = { 30 71 ?? }      //7-Technologies IGSS SCADA
               /* $s3 = { 0A F1 2? }      //Rslinx*/
            
        condition:
                $s0 and ($s1 or $s2 /*or $s3*/)
}

