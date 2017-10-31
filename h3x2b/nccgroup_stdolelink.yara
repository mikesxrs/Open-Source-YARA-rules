rule nccgroup_exploit_ole_stdolelink {
  meta:
    author = "David Cannings"
    description = "StdOleLink, potential 0day in April 2017"

  strings:
    // Parsers will open files without the full 'rtf'
    $header_rtf    = "{\\rt" nocase
    $header_office = { D0 CF 11 E0 }
    $header_xml    = "<?xml version=" nocase wide ascii

    // Marks of embedded
    // RTF format
    $embedded_object   = "\\object" nocase
    $embedded_objdata  = "\\objdata" nocase
    $embedded_ocx      = "\\objocx" nocase
    $embedded_objclass = "\\objclass" nocase
    $embedded_oleclass = "\\oleclsid" nocase

    // OLE format
    $embedded_root_entry = "Root Entry" wide
    $embedded_comp_obj   = "Comp Obj" wide
    $embedded_obj_info   = "Obj Info" wide
    $embedded_ole10      = "Ole10Native" wide

    $data0 = "00000300-0000-0000-C000-000000000046" nocase wide ascii
    $data1 = { 00 03 00 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
    $data2 = "OLE2Link" nocase wide ascii
    $data3 = "4f4c45324c696e6b" nocase wide ascii
    $data4 = "StdOleLink" nocase wide ascii
    $data5 = "5374644f6c654c696e6b" nocase wide ascii

  condition:
    // Mandatory header plus sign of embedding, then any of the others
    for any of ($header*) : ( @ == 0 ) and 1 of ($embedded*) and (1 of ($data*))
}
