rule ft_tar
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20151116"
      desc = "Signature to detect on TAR archive files"

   strings:
      $magic = { 75 73 74 61 72 }

   condition:
      $magic at 257
}
