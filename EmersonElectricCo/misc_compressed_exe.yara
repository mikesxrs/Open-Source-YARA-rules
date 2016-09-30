// Spec reference: http://forensicswiki.org/wiki/RAR#Format
rule compressed_exe_in_rar
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150813"
      desc = "Detect on evidence of a compressed executable within a RAR"

   strings:
      $rar = { 52 61 72 21 1A 07 00 }
      $file_header_part = { 74 [12] ( 00 | 01 | 02 | 03 | 04 | 05 ) [9] ( 30 | 31 | 32 | 33 | 34 | 35 ) }
      $exe_ext = ".exe"

   condition:
      $rar at 0 and for any r in (1..#file_header_part):
         // see if .exe is within the offset of the file archive header and however long the file name size is
         // file name begins 30 bytes away from start of header
         // file size is specified 24 bytes from the start
         // limitation is if the HIGH_PACK_SIZE or HIGH_UNP_SIZE optional values are set, accuracy will be effected
         ($exe_ext in (@file_header_part[r] + 30..@file_header_part[r] + 30 + uint16(@file_header_part[r] + 24)))
}

// Spec reference: https://en.wikipedia.org/wiki/Zip_(file_format)#File_headers
rule compressed_exe_in_zip
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150813"
      desc = "Detect on evidence of a compressed executable within a ZIP"

   strings:
      $pk = { 50 4B 03 04 }
      $exe_ext = ".exe"

   condition:
      $pk at 0 and for any p in (1..#pk):
         // see if .exe is within the offset of the local file header and however long the file name size is
         // file name begins 30 bytes away from the start of the local file header
         // file size is specified 26 bytes from the start
         ($exe_ext in (@pk[p] + 30..@pk[p] + 30 + uint16(@pk[p] + 26)))
}

rule misc_compressed_exe
{
   condition:
      compressed_exe_in_zip or compressed_exe_in_rar
}

