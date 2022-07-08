rule apt_CN_TwistedPanda_loader {
   meta:
      author = "Check Point Research"
      reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
      description = "Detect loader used by TwistedPanda"
      date = "2022-04-14"
      hash = "5b558c5fcbed8544cb100bd3db3c04a70dca02eec6fedffd5e3dcecb0b04fba0"
      hash = "efa754450f199caae204ca387976e197d95cdc7e83641444c1a5a91b58ba6198"
      
   strings:
      
      // 6A 40                                   push    40h ; '@'
      // 68 00 30 00 00                          push    3000h
      $seq1 = { 6A 40 68 00 30 00 00 }
      
      // 6A 00                                   push    0               ; lpOverlapped
      // 50                                      push    eax             ; lpNumberOfBytesRead
      // 6A 14                                   push    14h             ; nNumberOfBytesToRead
      // 8D ?? ?? ?? ?? ??                       lea     eax, [ebp+Buffer]
      // 50                                      push    eax             ; lpBuffer
        // 53                                      push    ebx             ; hFile
      // FF 15 04 D0 4C 70                       call    ds:ReadFile
      $seq2 = { 6A 00 50 6A 14 8D ?? ?? ?? ?? ?? 50 53 FF }
      // 6A 00                                   push    0
      // 6A 00                                   push    0
      // 6A 03                                   push    3
      // 6A 00                                   push    0
      // 6A 03                                   push    3
      // 68 00 00 00 80                          push    80000000h
      $seq3 = { 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 80 }
            
      // Decryption sequence
      $decryption = { 8B C? [2-3] F6 D? 1A C? [2-3] [2-3] 30 0? ?? 4? }
 
   condition:
      // MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
        
      // ... PE signature at offset stored in MZ header at 0x3C
      uint32(uint32(0x3C)) == 0x00004550 and 
      filesize < 3000KB and all of ($seq*) and $decryption
}
