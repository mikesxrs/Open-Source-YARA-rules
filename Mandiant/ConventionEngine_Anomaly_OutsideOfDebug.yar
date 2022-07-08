rule ConventionEngine_Anomaly_OutsideOfDebug
{
    meta:
        author = "@stvemillertime"
        description = "Searching for PE files with PDB path keywords, terms or anomalies."
        reference = "https://www.mandiant.com/resources/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware"
   strings:
        $anchor = "RSDS"
        $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\.pdb\x00/
   condition:
        (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $anchor and $pcre and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address == 0
}

