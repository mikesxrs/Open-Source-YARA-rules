import "pe"

rule W32ChirB_eml {
   meta:
      description = "readme.eml - Chir.B"
      author = "wit0k"
      reference = ""
      date = "2018-08-30"
      hash1 = "d41a5c4fe5171cbfe26ef04da347188d1c22e34d2d4cdffd833f38d61e3b6ec8"
   strings:
      $s4 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:THE-CID height=3D0 width=3D0></iframe></body></html>" fullword ascii
      $s6 = "UAToCwAAAGCJGIlQBPzzpGHP+maPAGaPQAaLdQiLfQyLTRDM+2HJwgwA6cgAAABgi0UIagBQUGoA/5aQAAAAYcnCBAAAAAAAAAAAAMMAAAAAAAAAAAAAAAAAAAA=" fullword ascii
      $s7 = /FROM: .{1,20}@yahoo\.com/ fullword ascii nocase
      $s8 = /Content-Type: audio\/x-wav; name=.{1,20}.exe/ fullword ascii nocase
      $s11 = "dmFTY3JpcHQiPndpbmRvdy5vcGVuKCJyZWFkbWUuZW1sIiwgbnVsbCwicmVzaXphYmxlPW5vLHRvcD02MDAwLGxlZnQ9NjAwMCIpPC9zY3JpcHQ+PC9odG1sPgBYanhQ" ascii /* base64 encoded string 'vaScript">window.open("readme.eml", null,"resizable=no,top=6000,left=6000")</script></html>...' */
      $s18 = "TVpQAAIAAAAEAA8A//8AALgAAAAAAAAAQAAaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAALoQAA4ftAnNIbgBTM0hkJBUaGlzIHByb2dyYW0gbXVz" ascii /* base64 encoded string 'MZP...This program mus' */
   condition:
      ( uint16(0) == 0x20ce and filesize < 120KB and ( 3 of them )
      ) or ( all of them )
}

rule W32ChirB_pe_infector {
   meta:
      description = "pp.exe - Chir.B"
      author = "wit0k"
      reference = ""
      date = "2018-08-31"
      hash1 = "d2f46265c39c21bc544b9ab4fad708bae7f33defff32f280806d48e3eb31e510"
   strings:
      $s1 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:THE-CID height=3D0 width=3D0></iframe></body></html>" fullword ascii
      $s2 = "<html><script language=\"JavaScript\">window.open(\"readme.eml\", null,\"resizable=no,top=6000,left=6000\")</script></html>" fullword ascii
      $s3 = /FROM: .{1,20}@yahoo\.com/ fullword ascii nocase
      $s4 = /Content-Type: audio\/x-wav; name=.{1,20}.exe/ fullword ascii nocase
      $s5 = "\\runouce.exe" fullword ascii
      $s6 = "Net Send * My god! Some one killed ChineseHacker-2 Monitor" fullword ascii
      $s7 = /readme\.eml/ fullword ascii
      $s8 = "Runonce" fullword ascii
      $s9 = "SUBJECT: %s is comming!" fullword ascii
      $s10 = /MAIL FROM: .{1,20}@btamail\.net.\cn/ fullword ascii
      $s11 = "Content-id: THE-CID" fullword ascii
      $s12 = "btamail.net.cn" fullword ascii
      $ds1 = "This program cannot be run in DOS mode"
   condition:
      (uint16(0) == 0x5a4d or uint16(0) == 0x4d5a ) and ( 8 of them ) and (filesize < 120KB) and not $ds1
}

rule W32ChirB_infected_pe {
   meta:
      description = "pp.exe appended to an exe"
      author = "wit0k"
      reference = ""
      date = "2018-08-31"
      hash1 = "6ca9ff59325d13f1dd69855d88633814c685bcf0db44415888a3ceeeab731493"
   strings:
      $s1 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:THE-CID height=3D0 width=3D0></iframe></body></html>" fullword ascii
      $s2 = "<html><script language=\"JavaScript\">window.open(\"readme.eml\", null,\"resizable=no,top=6000,left=6000\")</script></html>" fullword ascii
      $s3 = /FROM: .{1,20}@yahoo\.com/ fullword ascii nocase
      $s4 = /Content-Type: audio\/x-wav; name=.{1,20}.exe/ fullword ascii nocase
      $s5 = "\\runouce.exe" fullword ascii
      $s6 = "Net Send * My god! Some one killed ChineseHacker-2 Monitor" fullword ascii
      $s7 = "readme.eml" fullword ascii
      $s8 = "Runonce" fullword ascii
      $s9 = "SUBJECT: %s is comming!" fullword ascii
      $s10 = /MAIL FROM: .{1,20}@btamail\.net.\cn/ fullword ascii
      $s11 = "Content-id: THE-CID" fullword ascii
      $s12 = "btamail.net.cn" fullword ascii
      $s13 = "ChineseHacker-2" ascii wide
      $b14 = { 60 E8 E6 19 00 00 8B 74 24 20 E8 08 00 00 00 61 } /* Begining of injected code */
      $ds1 = "This program cannot be run in DOS mode"
   condition:
      ( uint16(0) == 0xe860 and
         ( 8 of them ) and  ( $b14 at pe.entry_point ) and $ds1
      ) or ( all of them )
}


rule W32ChirB_LastResort
{
    meta:
        Description = ""

    strings:
        $a = "runouce.exe" ascii wide
        $b = /.{1,20}@btamail.net.cn/ fullword ascii nocase
        $c = "ChineseHacker-2" ascii wide

    condition:
        all of them
}

