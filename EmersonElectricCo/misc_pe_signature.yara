import "pe"

rule misc_pe_signature
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150911"
      desc = "Triggers if an authenticode signature is present within a PE file (if the PE is signed for example)"

   condition:
      pe.number_of_signatures > 0
}
