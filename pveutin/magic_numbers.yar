/*Magic Number rules
This rule set defines a list of file signature to help identify files
https://github.com/pveutin/YaraRules/blob/master/filesig.yar
*/


//Documents

rule office_magic_bytes
{
  strings:
    $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
  condition:
    $magic
}

rule chm_file
{
  strings:
    $magic = { 49 54 53 46 03 00 00 00  60 00 00 00 01 00 00 00 }
  condition:
    $magic
}

rule excel_document
{
  strings:
    $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $workbook = "Workbook" wide nocase
    $msexcel = "Microsoft Excel" nocase
  condition:
    all of them
}

rule word_document
{
  strings:
    $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $worddoc = "WordDocument" wide
    $msworddoc = "MSWordDoc" nocase
  condition:
    $rootentry and ($worddoc or $msworddoc)
}

rule powerpoint_document
{
  strings:
    $pptdoc = "PowerPoint Document" wide nocase
    $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  condition:
    all of them
}

rule pdf_document
{
  strings:
    $a = "%PDF-"
  condition:
    $a at 0
}


//Programs

rule mz_executable // from YARA user's manual
{
  condition:
  // MZ signature at offset 0 and ...
  uint16(0) == 0x5A4D and
  // ... PE signature at offset stored in MZ header at 0x3C
  uint32(uint32(0x3C)) == 0x00004550
}

//Archives
rule zip_file
{
  strings:
    $magic = { 50 4b 03 04 }
    $magic2 = { 50 4b 05 06 }
    $magic3 = { 50 4b 07 08 }
  condition:
    ($magic at 0) or ($magic2 at 0) or ($magic3 at 0)
}

rule sevenzip_file
{
  strings:
    $magic = { 37 7A BC AF 27 1C }
  condition:
    $magic at 0
}

rule rar_file
{
  strings:
    $rar = { 52 61 72 21 1A 07 00 }
    $rar5 = { 52 61 72 21 1A 07 01 00 }
  condition:
    ($rar at 0) or ($rar5 at 0)
}

//Pictures
rule gif_file
{
  strings:
    $gif89a = { 47 49 46 38 39 61 }
    $gif87a = { 47 49 46 38 37 61 }
  condition:
    ( $gif89a at 0 ) or ( $gif87a at 0 )
}

rule png_file
{
  strings :
    $magic = { 89 50 4E 47 0D 0A 1A 0A }
  condition:
    $magic at 0
}

rule bmp_file
{
  strings:
    $magic = "BM"
  condition:
    $magic at 0
}

rule jpeg_file
{
  strings:
    $jpeg = { FF D8 FF E0 }
    $jpeg1 = { FF D8 FF E1 }
  condition:
    ($jpeg at 0) or ($jpeg1 at 0)
}