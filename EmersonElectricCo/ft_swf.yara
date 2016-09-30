rule ft_swf_cws
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150318"
      desc = "File type signature for regular compressed SWF files"

   strings:
      $cws = "CWS"

   condition:
      $cws at 0
}

rule ft_swf_fws
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150318"
      desc = "File type signature for basic SWF files."

   strings:
      $fws = "FWS"

   condition:
      $fws at 0
}

rule ft_swf_zws
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150318"
      desc = "File type signature for SWF files compressed with LZMA compression, uncommonly observed"

   strings:
      $zws = "ZWS"

   condition:
      $zws at 0
}

rule ft_swf
{
   condition:
      ft_swf_zws or ft_swf_fws or ft_swf_cws
}

