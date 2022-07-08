rule PDB_Header_V7
{
    meta:
        author="@stvemillertime"
        description = "This looks for PDB files based on headers."
        reference = "https://www.mandiant.com/resources/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware"
    strings:
        //$string = "Microsoft C/C++ MSF 7.00"
        $hex = {4D696372 6F736F66 7420432F 432B2B20 4D534620 372E3030}
    condition:
        $hex at 0
}
