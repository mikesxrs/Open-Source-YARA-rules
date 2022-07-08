rule ConventionEngine_Anomaly_NonAscii
{
    meta:
        author = "@stvemillertime"
        reference = "https://www.mandiant.com/resources/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware"
    strings:
        $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,500}[^\x00-\x7F]{1,}[\x00-\xFF]{0,500}\.pdb\x00/
    condition:
        (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}
