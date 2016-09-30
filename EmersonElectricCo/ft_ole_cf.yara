rule ft_ole_cf
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20141202"
      desc = "Detect file magic indicative of OLE CF files (commonly used by early versions of MS Office)."

   strings:
      $magic = { D0 CF 11 E0 A1 B1 1A E1 }

   condition:
      $magic at 0
}
