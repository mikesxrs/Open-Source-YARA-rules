rule ft_zip
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20141217"
      desc = "File type signature for basic ZIP files."

   strings:
      $pk = { 50 4B 03 04 }

   condition:
      $pk at 0
}
