rule ft_gzip
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20151116"
      desc = "Trigger on magic of GZip compressed files"

   strings:
      $magic = { 1f 8b 08 }

   condition:
      $magic at 0
}
