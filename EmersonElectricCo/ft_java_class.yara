rule ft_java_class
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20160126"
      desc = "File magic for detecting a Java bytecode file."

   strings:
      $class = { CA FE BA BE }

   condition:
      $class at 0
}
