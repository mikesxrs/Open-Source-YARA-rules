rule ft_pdf
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20141230"
      desc = "Signature to trigger on PDF file magic."

   strings:
      $pdf = "%PDF"

   condition:
      $pdf in (0 .. 1024)
}
