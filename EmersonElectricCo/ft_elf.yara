rule ft_elf
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20160121"
      desc = "File magic for ELF files"

   strings:
      $magic = { 7f 45 4c 46 }

   condition:
      $magic at 0 
}
