rule apt_CN_TwistedPanda_SPINNER_2 {
   meta:
      author = "Check Point Research"
      description = "Detect an older variant of SPINNER payload used by TwistedPanda"
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      date = "2022-04-14"
      hash = "28ecd1127bac08759d018787484b1bd16213809a2cc414514dc1ea87eb4c5ab8"
      
   strings:
      // C7 ?? ?? ?? 00 00 00                                mov     dword ptr [eax+??], ??
      // C7 ?? ?? ?? 00 00 00                                mov     dword ptr [eax+??], ??
      // C6                                                  mov     byte ptr [eax], 0
      $config_init = { C7 [3] 00 00 00 C7 [3] 00 00 00 C6 }
      $c2_cmd_1 = { 01 00 03 10 }
      $c2_cmd_2 = { 02 00 01 10 }
      $c2_cmd_3 = { 01 00 01 10 }
      $c2_cmd_4 = { 01 00 00 10 }
      $c2_cmd_5 = { 02 00 00 10 }
      // 80 B3 ?? ?? ?? ?? ??                    xor     ds:dd_encrypted_url[ebx], 50h
      // 8D BB ?? ?? ?? ??                       lea     edi, dd_encrypted_url[ebx]
      // 8B 56 14                                mov     edx, [esi+14h]
      // 8B C2                                   mov     eax, edx
      // 8B 4E 10                                mov     ecx, [esi+10h]
      // 2B C1                                   sub     eax, ecx
      // 83 F8 01                                cmp     eax, 1
      $decryption = { 80 B3 [5] 8D BB [4] 8B 56 14 8B C2 8B 4E 10 2B C1 83 F8 01 }
 
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB  and #config_init > 10 and 2 of ($c2_cmd_*) and $decryption
}
