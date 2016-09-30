rule ft_jar
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150810"
      desc = "Signature to detect JAR files"

   strings:
      $pk_header = { 50 4B 03 04 }
      $jar = "META-INF/MANIFEST.MF"

   condition:
      $pk_header at 0 and $jar
}
