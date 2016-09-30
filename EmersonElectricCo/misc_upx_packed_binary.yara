import "pe"

rule misc_upx_packed_binary
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150520"
      desc = "Detect section names indicative of UPX packed PE files"

   condition:
      (pe.sections[0].name == "UPX0" and pe.sections[1].name == "UPX1")
}
