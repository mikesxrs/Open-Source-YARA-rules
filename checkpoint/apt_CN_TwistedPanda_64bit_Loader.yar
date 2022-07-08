rule apt_CN_TwistedPanda_64bit_Loader {
   meta:
      author = "Check Point Research"
      description = "Detect the 64bit Loader DLL used by TwistedPanda"
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      date = "2022-04-14"
      hash = "e0d4ef7190ff50e6ad2a2403c87cc37254498e8cc5a3b2b8798983b1b3cdc94f"
      
   strings:
      // 48 8D ?? ?? ?? ?? ?? ?? ??              lea     rdx, ds:2[rdx*2]
      // 48 8B C1                                mov     rax, rcx
      // 48 81 ?? ?? ?? ?? ??                    cmp     rdx, 1000h
      // 72 ??                                   jb      short loc_7FFDF0BA1B48
      $path_check = { 48 8D [6] 48 8B ?? 48 81 [5] 72 }
      // 48 8B D0                                mov     rdx, rax        ; lpBuffer
      // 41 B8 F0 16 00 00                       mov     r8d, 16F0h      ; nNumberOfBytesToRead
      // 48 8B CF                                mov     rcx, rdi        ; hFile
      // 48 8B D8                                mov     rbx, rax
      // FF ?? ?? ?? ??                          call    cs:ReadFile
      $shellcode_read = { 48 8B D0 41 B8 F0 16 00 00 48 8B CF 48 8B D8 FF} 
      // BA F0 16 00 00                          mov     edx, 16F0h      ; dwSize
      // 44 8D 4E 40                             lea     r9d, [rsi+40h]  ; flProtect
      // 33 C9                                   xor     ecx, ecx        ; lpAddress
      // 41 B8 00 30 00 00                       mov     r8d, 3000h      ; flAllocationType
      // FF ?? ?? ?? ?? ??                       call    cs:VirtualAlloc
     $shellcode_allocate = { BA F0 16 00 00 44 8D 4E 40 33 C9 41 B8 00 30 00 00 FF }
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB  and $path_check and $shellcode_allocate and $shellcode_read
}
