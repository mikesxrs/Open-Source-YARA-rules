rule ft_rar
{
   meta:
      author = "James Ferrer"
      company = "Emerson"
      lastmod = "20150107"
      desc = "File type signature for basic .rar files"

   strings:
      $Rar = {52 61 72 21 1A 07} 
      
   condition:

      $Rar at 0
}
