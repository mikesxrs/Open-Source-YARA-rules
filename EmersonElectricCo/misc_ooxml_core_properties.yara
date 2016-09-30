rule misc_ooxml_core_properties
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150505"
      desc = "Identify meta xml content within OOXML documents"

   strings:
      $xml = "<?xml version="
      $core = "<cp:coreProperties xmlns:cp"

   condition:
      $xml at 0 and $core
}

