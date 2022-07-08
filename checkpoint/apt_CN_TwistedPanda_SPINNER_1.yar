rule apt_CN_TwistedPanda_SPINNER_1 {
   meta:
      author = "Check Point Research"
      description = "Detect the obfuscated variant of SPINNER payload used by TwistedPanda"
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      date = "2022-04-14"
      hash = "a9fb7bb40de8508606a318866e0e5ff79b98f314e782f26c7044622939dfde81"
      
   strings:
      // C7 ?? ?? ?? 00 00 00                                mov     dword ptr [eax+??], ??
      // C7 ?? ?? ?? 00 00 00                                mov     dword ptr [eax+??], ??
      // C6                                                  mov     byte ptr [eax], 0
      $config_init = { C7 ?? ?? ?? 00 00 00 C7 ?? ?? ?? 00 00 00 C6 }
      $c2_cmd_1 = { 01 00 03 10}
      $c2_cmd_2 = { 02 00 01 10}
      $c2_cmd_3 = { 01 00 01 10}
      // 8D 83 ?? ?? ?? ??                                   lea     eax, xor_key[ebx]
      // 80 B3 ?? ?? ?? ?? ??                                xor     xor_key[ebx], 50h
      // 89 F1                                               mov     ecx, esi        ; this
      // 6A 01                                               push    1               ; Size
      // 50                                                  push    eax             ; Src
      // E8 ?? ?? ?? ??                                      call    str_append
      // 80 B3 ?? ?? ?? ?? ??                                xor     xor_key[ebx], 50h
      $decryption = { 8D 83 [4] 80 B3 [5] 89 F1 6A 01 50 E8 [4] 80 B3 }
 
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB  and #config_init > 10 and 2 of ($c2_cmd_*) and $decryption
}
