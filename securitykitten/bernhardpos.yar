rule BernhardPOS {
   meta:
     author = "Nick Hoffman / Jeremy Humble"
     last_update = "2015-07-14"
     source = "Morphick Inc."
     description = "BernhardPOS Credit Card dumping tool"
     reference = "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
     md5 = "e49820ef02ba5308ff84e4c8c12e7c3d"
   strings:
     /*
     33C0        xor    eax, eax
     83C014        add    eax, 0x14
     83E814        sub    eax, 0x14
     64A130000000        mov    eax, dword ptr fs:[0x30]
     83C028        add    eax, 0x28
     83E828        sub    eax, 0x28
     8B400C        mov    eax, dword ptr [eax + 0xc]
     83C063        add    eax, 0x63
     83E863        sub    eax, 0x63
     8B4014        mov    eax, dword ptr [eax + 0x14]
     83C078        add    eax, 0x78
     83E878        sub    eax, 0x78
     8B00        mov    eax, dword ptr [eax]
     05DF030000        add    eax, 0x3df
     2DDF030000        sub    eax, 0x3df
     8B00        mov    eax, dword ptr [eax]
     83C057        add    eax, 0x57
     83E857        sub    eax, 0x57
     8B4010        mov    eax, dword ptr [eax + 0x10]
     83C063        add    eax, 0x63
     */
     $shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }
     $mutex_name = "OPSEC_BERNHARD" 
     $build_path = "C:\\bernhard\\Debug\\bernhard.pdb" 
     /*
     55        push    ebp
     8BEC        mov    ebp, esp
     83EC50        sub    esp, 0x50
     53        push    ebx
     56        push    esi
     57        push    edi
     A178404100        mov    eax, dword ptr [0x414078]
     8945F8        mov    dword ptr [ebp - 8], eax
     668B0D7C404100        mov    cx, word ptr [0x41407c]
     66894DFC        mov    word ptr [ebp - 4], cx
     8A157E404100        mov    dl, byte ptr [0x41407e]
     8855FE        mov    byte ptr [ebp - 2], dl
     8D45F8        lea    eax, dword ptr [ebp - 8]
     50        push    eax
     FF150CB04200        call    dword ptr [0x42b00c]
     8945F0        mov    dword ptr [ebp - 0x10], eax
     C745F400000000        mov    dword ptr [ebp - 0xc], 0
     EB09        jmp    0x412864
     8B45F4        mov    eax, dword ptr [ebp - 0xc]
     83C001        add    eax, 1
     8945F4        mov    dword ptr [ebp - 0xc], eax
     8B4508        mov    eax, dword ptr [ebp + 8]
     50        push    eax
     FF150CB04200        call    dword ptr [0x42b00c]
     3945F4        cmp    dword ptr [ebp - 0xc], eax
     7D21        jge    0x412894
     8B4508        mov    eax, dword ptr [ebp + 8]
     0345F4        add    eax, dword ptr [ebp - 0xc]
     0FBE08        movsx    ecx, byte ptr [eax]
     8B45F4        mov    eax, dword ptr [ebp - 0xc]
     99        cdq
     F77DF0        idiv    dword ptr [ebp - 0x10]
     0FBE5415F8        movsx    edx, byte ptr [ebp + edx - 8]
     33CA        xor    ecx, edx
     8B4508        mov    eax, dword ptr [ebp + 8]
     0345F4        add    eax, dword ptr [ebp - 0xc]
     8808        mov    byte ptr [eax], cl
     EBC7        jmp    0x41285b
     5F        pop    edi
     5E        pop    esi
     5B        pop    ebx
     8BE5        mov    esp, ebp
     5D        pop    ebp
     */
     $string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }
   condition:
     any of them
 }

