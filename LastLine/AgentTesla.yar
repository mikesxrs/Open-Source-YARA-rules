rule Agent_Tesla : Agent_Tesla
{
     meta:
          author = "LastLine"
          reference = "https://www.lastline.com/labsblog/surge-of-agent-tesla-threat-report/"
     strings:
          $pass = "amp4Z0wpKzJ5Cg0GDT5sJD0sMw0IDAsaGQ1Afik6NwXr6rrSEQE=" fullword ascii wide nocase
          $salt = "aGQ1Afik6NampDT5sJEQE4Z0wpsMw0IDAD06rrSswXrKzJ5Cg0G=" fullword ascii wide nocase
 
     condition:
           uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and all of them
}
