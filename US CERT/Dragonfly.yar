rule APT_malware_1
{
meta:
      description = "inveigh pen testing tools & related artifacts"
      author = "US-CERT Code Analysis Team"    
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017/07/17"
      hash0 = "61C909D2F625223DB2FB858BBDF42A76"
      hash1 = "A07AA521E7CAFB360294E56969EDA5D6"
      hash2 = "BA756DD64C1147515BA2298B6A760260"
      hash3 = "8943E71A8C73B5E343AA9D2E19002373"
      hash4 = "04738CA02F59A5CD394998A99FCD9613"
      hash5 = "038A97B4E2F37F34B255F0643E49FC9D"
      hash6 = "65A1A73253F04354886F375B59550B46"
      hash7 = "AA905A3508D9309A93AD5C0EC26EBC9B"
      hash8 = "5DBEF7BDDAF50624E840CCBCE2816594"
      hash9 = "722154A36F32BA10E98020A8AD758A7A"
      hash10 = "4595DBE00A538DF127E0079294C87DA0"
strings:
      $s0 = "file://"
      $s1 = "/ame_icon.png"
      $s2 = "184.154.150.66"
      $s3 = { 87D081F60C67F5086A003315D49A4000F7D6E8EB12000081F7F01BDD21F7DE }
      $s4 = { 33C42BCB333DC0AD400043C1C61A33C3F7DE33F042C705B5AC400026AF2102 }
      $s5 = "(g.charCodeAt(c)^l[(l[b]+l[e])%256])"
      $s6 = "for(b=0;256>b;b++)k[b]=b;for(b=0;256>b;b++)"
      $s7 = "VXNESWJfSjY3grKEkEkRuZeSvkE="
      $s8 = "NlZzSZk="
      $s9 = "WlJTb1q5kaxqZaRnser3sw=="
      $s10 = "for(b=0;256>b;b++)k[b]=b;for(b=0;256>b;b++)"
      $s11 = "fromCharCode(d.charCodeAt(e)^k[(k[b]+k[h])%256])"
      $s12 = "ps.exe -accepteula \\%ws% -u %user% -p %pass% -s cmd /c netstat"
      $s13 = { 22546F6B656E733D312064656C696D733D5C5C222025254920494E20286C6973742E74787429 }
      $s14 = { 68656C6C2E657865202D6E6F65786974202D657865637574696F6E706F6C69637920627970617373202D636F6D6D616E6420222E202E5C496E76656967682E70 }
      $s15 = { 476F206275696C642049443A202266626433373937623163313465306531 }
 
 
//inveigh pentesting tools
 
      $s16 = { 24696E76656967682E7374617475735F71756575652E4164642822507265737320616E79206B657920746F2073746F70207265616C2074696D65 }
 
//specific malicious word document PK archive
 
      $s17 = { 2F73657474696E67732E786D6CB456616FDB3613FEFE02EF7F10F4798E64C54D06A14ED125F19A225E87C9FD0194485B }
      $s18 = { 6C732F73657474696E67732E786D6C2E72656C7355540500010076A41275780B0001040000000004000000008D90B94E03311086EBF014D6F4D87B48214471D2 }
      $s19 = { 8D90B94E03311086EBF014D6F4D87B48214471D210A41450A0E50146EBD943F8923D41C9DBE3A54A240ACA394A240ACA39 }
      $s20 = { 8C90CD4EEB301085D7BD4F61CDFEDA092150A1BADD005217B040E10146F124B1F09FEC01B56F8FC3AA9558B0B4 }
      $s21 = { 8C90CD4EEB301085D7BD4F61CDFEDA092150A1BADD005217B040E10146F124B1F09FEC01B56F8FC3AA9558B0B4 }
      $s22 = "5.153.58.45"
      $s23 = "62.8.193.206"
      $s24 = "/1/ree_stat/p"
      $s25 = "/icon.png"
      $s26 = "/pshare1/icon"
      $s27 = "/notepad.png"
      $s28 = "/pic.png"
      $s29 = "http://bit.ly/2m0x8IH"
     
condition:
      ($s0 and $s1 or $s2) or ($s3 or $s4) or ($s5 and $s6 or $s7 and $s8 and $s9) or ($s10 and $s11) or ($s12 and $s13) or ($s14) or ($s15) or ($s16) or ($s17) or ($s18) or ($s19) or ($s20) or ($s21) or ($s0 and $s22 or $s24) or ($s0 and $s22 or $s25) or ($s0 and $s23 or $s26) or ($s0 and $s22 or $s27) or ($s0 and $s23 or $s28) or ($s29)
}
 
rule APT_malware_2
{
meta:
      description = "rule detects malware"
      author = "other"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
strings:
      $api_hash = { 8A 08 84 C9 74 0D 80 C9 60 01 CB C1 E3 01 03 45 10 EB ED }
      $http_push = "X-mode: push" nocase
      $http_pop = "X-mode: pop" nocase
condition:
      any of them
}
 
rule Query_XML_Code_MAL_DOC_PT_2
{
      meta:
            name= "Query_XML_Code_MAL_DOC_PT_2"
            author = "other"
      strings:
            $zip_magic = { 50 4b 03 04 }
            $dir1 = "word/_rels/settings.xml.rels"
            $bytes = {8c 90 cd 4e eb 30 10 85 d7}
      condition:
            $zip_magic at 0 and $dir1 and $bytes
}
 
rule Query_Javascript_Decode_Function
{
meta:
      name= "Query_Javascript_Decode_Function"
      author = "other
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
strings:
      $decode1 = {72 65 70 6C 61 63 65 28 2F 5B 5E 41 2D 5A 61 2D 7A 30 2D 39 5C 2B 5C 2F 5C 3D 5D 2F 67 2C 22 22 29 3B}
      $decode2 = {22 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F 3D 22 2E 69 6E 64 65 78 4F 66 28 ?? 2E 63 68 61 72 41 74 28 ?? 2B 2B 29 29}
      $decode3 = {3D ?? 3C 3C 32 7C ?? 3E 3E 34 2C ?? 3D 28 ?? 26 31 35 29 3C 3C 34 7C ?? 3E 3E 32 2C ?? 3D 28 ?? 26 33 29 3C 3C 36 7C ?? 2C ?? 2B 3D [1-2] 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29 2C 36 34 21 3D ?? 26 26 28 ?? 2B 3D 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29}
      $decode4 = {73 75 62 73 74 72 69 6E 67 28 34 2C ?? 2E 6C 65 6E 67 74 68 29}
      $func_call="a(\""
condition:
      filesize < 20KB and #func_call > 20 and all of ($decode*)
}
 
rule Query_XML_Code_MAL_DOC
{
meta:
      name= "Query_XML_Code_MAL_DOC"
      author = "other"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
strings:
      $zip_magic = { 50 4b 03 04 }
      $dir = "word/_rels/" ascii
      $dir2 = "word/theme/theme1.xml" ascii
      $style = "word/styles.xml" ascii
condition:
      $zip_magic at 0 and $dir at 0x0145 and $dir2 at 0x02b7 and $style at 0x08fd
}
