rule apt_CN_TwistedPanda_droppers {
   meta:
      author = "Check Point Research"
      description = "Detect droppers used by TwistedPanda"
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      date = "2022-04-14"
      hash = "59dea38da6e515af45d6df68f8959601e2bbf0302e35b7989e741e9aba2f0291"
      hash = "8b04479fdf22892cdfebd6e6fbed180701e036806ed0ddbe79f0b29f73449248"
      hash = "f29a0cda6e56fc0e26efa3b6628c6bcaa0819a3275a10e9da2a8517778152d66"
      
   strings:
     // 81 FA ?? ?? ?? ??                                   cmp     edx, 4BED1896h
     // 75 ??                                               jnz     short loc_140001829
     // E8 ?? ?? ?? ??                                      call    sub_1400019D0
     // 48 89 05 ?? ?? ?? ??                                mov     cs:qword_14001ED38, rax
     // E? ?? ?? ?? ??                                      jmp     loc_1400018DD
      $switch_control = { 81 FA [4] 75 ?? E8 [4] 48 89 05 [4] E? }
     // 41 0F ?? ??                                         movsx   edx, byte ptr [r9]
     // 44 ?? ??                                            or      r8d, edx
     // 41 ?? ?? 03                                         rol     r8d, 3
     // 41 81 ?? ?? ?? ?? ??                                xor     r8d, 0EF112233h
     // 41 ?? ??                                            mov     eax, r10d
      $byte_manipulation = { 41 0F [2] 44 [2] 41 [2] 03 41 81 [5] 41 }
     // %public%
     $stack_strings_1 = { 25 00 70 00 }
     $stack_strings_2 = { 75 00 62 00 }
     $stack_strings_3 = { 6C 00 69 00 }
     $stack_strings_4 = { 63 00 25 00 }
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB  and #switch_control > 8 and all of ($stack_strings_*) and $byte_manipulation
}
