rule PowerPoint_Embedded_OLE
{
  meta:
    description = "PPSX/PPTX Containers containing embedded data."
    author = "PhishMe"
  strings:
    $magic = {50 4b}
    $meta1 = "ppt/embeddings/oleObject"     
    $meta2 = "ppt/slides/"
  condition:
    $magic at 0 and all of ($meta*)
}