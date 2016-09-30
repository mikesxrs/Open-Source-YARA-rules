rule ft_exe
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20141217"
      desc = "Simple signature to trigger on PE files."

   strings:
      $mz = "MZ"

   condition:
      $mz at 0
}
