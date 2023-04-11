rule ducktail_artifacts
{
    meta:
        author="WithSecure"
        description="Detects artifacts found in files associated to DUCKTAIL malware"
        date="2022-07-18"
        version="1.0"
        reference="https://labs.withsecure.com/publications/ducktail"
        hash1="3dbd9e1c3d0fd6358d4adcba04fdfc0b6e8acc49"
        hash2="9370243589327b458486e3f7637779c2a96b4250"
        hash3="b98170b18b906aee771dbd4dbd31e5963a90a50e"
        report = "https://www.withsecure.com/en/expertise/research-and-innovation/research/ducktail-an-infostealer-malware"
    strings:
        $pdb_path_1 = /[a-z]\:\\projects\\(viruttest|virot)\\/i nocase ascii
        $pdb_path_2 = /[a-z]\:\\users\\ductai\\/i nocase ascii
        $pdb_path_3 = "\\dataextractor.pdb" nocase ascii
        $email = "ductai2308@gmail.com" wide ascii
     condition:
        uint16(0) == 0x5A4D
        and any of them
}