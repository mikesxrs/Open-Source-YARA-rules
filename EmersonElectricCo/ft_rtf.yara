rule ft_rtf
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20141204"
      desc = "Hit on RTF files by triggering on RTF file magic"

   strings:
      $rtf = { 7B 5C 72 74 66 }

   condition:
      $rtf at 0
}
