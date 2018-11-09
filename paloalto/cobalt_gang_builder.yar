rule cmstp_macro_builder_rev_a
{
    meta:
        description="CMSTP macro builder based on variable names and runtime invoke"
        author="Palo Alto Networks Unit42"
        reference = "https://researchcenter.paloaltonetworks.com/2018/10/unit42-new-techniques-uncover-attribute-cobalt-gang-commodity-builders-infrastructure-revealed/"
    strings:
        $method="CallByName"
        $varexp=/[A-Za-z]k[0-9]{2}([0-9]{1})/
    condition:
        $method and
        #method == 2 and
        #varexp > 10
 
}
 
rule cmstp_macro_builder_rev_b {
    meta:
        description="CMSTP macro builder based on routines and functions names and runtime invoke"
        author="Palo Alto Networks Unit42"
        reference = "https://researchcenter.paloaltonetworks.com/2018/10/unit42-new-techniques-uncover-attribute-cobalt-gang-commodity-builders-infrastructure-revealed/"
    strings:
        $func=/Private Function [A-Za-z]{1,5}[0-9]{2,3}\(/
        $sub=/Sub [A-Za-z]{1,5}[0-9]{2,5}\(/
        $call="CallByName"
    condition:
        $call and
        #func > 1 and
        #sub > 1
}

rule cobaltgang_pdf_metadata_rev_a{
    meta:
        description="Find documents saved from the same potential Cobalt Gang PDF template"
        author="Palo Alto Networks Unit 42"
        reference = "https://researchcenter.paloaltonetworks.com/2018/10/unit42-new-techniques-uncover-attribute-cobalt-gang-commodity-builders-infrastructure-revealed/"
    strings:
             $ = "<xmpMM:DocumentID>uuid:31ac3688-619c-4fd4-8e3f-e59d0354a338" ascii wide
    condition:
             any of them
}
