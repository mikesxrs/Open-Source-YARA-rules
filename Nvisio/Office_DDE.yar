
// YARA rules Office DDE
// NVISO 2017/10/10 - 2017/10/12
// https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/
  
rule Office_DDEAUTO_field {
  meta:
  	reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
  strings:
    $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
  condition:
    $a
}
  
rule Office_DDE_field {
  meta:
  	reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
  strings:
    $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
  condition:
    $a
}
 
rule Office_OLE_DDEAUTO {
  meta:
  	reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
  strings:
    $a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase
  condition:
    uint32be(0) == 0xD0CF11E0 and $a
}
 
rule Office_OLE_DDE {
  meta:
  	reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
  strings:
    $a = /\x13\s*DDE\b[^\x14]+/ nocase
  condition:
    uint32be(0) == 0xD0CF11E0 and $a
}
