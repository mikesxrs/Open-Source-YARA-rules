rule ConventionEngine_Anomaly_MultiPDB_Triple
{
    meta:
        author = "@stvemillertime"
        reference = "https://www.mandiant.com/resources/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware"
    strings:
        $anchor = "RSDS"
        $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}\.pdb\x00/
    condition:
        (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and #anchor == 3 and #pcre == 3
}
