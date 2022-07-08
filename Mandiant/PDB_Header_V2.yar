rule PDB_Header_V2
{
    meta:
        author="@stvemillertime"
        description = "This looks for PDB files based on headers."
        reference = "https://www.mandiant.com/resources/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware"
    strings:
        //$string = "Microsoft C/C++ program database 2.00"
        $hex = {4D696372 6F736F66 7420432F 432B2B20 70726F67 72616D20 64617461 62617365 20322E30 300D0A}
    condition:
        $hex at 0
