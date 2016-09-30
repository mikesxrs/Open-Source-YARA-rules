rule ft_cab
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150723"
      desc = "File magic for CABs (Microsoft Cabinet Files)"

   strings:
      $cab = { 4D 53 43 46 }

   condition:
      $cab at 0
}
