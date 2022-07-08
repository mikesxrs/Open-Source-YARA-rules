
import "pe"
rule TTP_Mutation_StackPush_Windows_DLLs {
 meta:
   author = "Stairwell"
   description = "Searching for PE files with mutations of odd, rare, or interesting string equities. Here we look for strings from common PE strings, DLLs and functions in pseudo stack strings form, where the string pushed onto the stack 4 bytes at a time using PUSH 0x68, appearing in reverse four byte chunk order, where the PUSH which shows up as an ASCII letter h."
   reference = "https://stairwell.com/news/threat-research-detection-research-labeled-malware-corpus-yara-testing/"
 strings:
   $a0_kernel32dll = "h.dllhel32hkern" ascii nocase
   $a1_ws2_32dll = "hllh32.dhws2_" ascii nocase
   $a2_msvcrtdll = "hllhrt.dhmsvc" ascii nocase
   $a3_KernelBasedll = "hllhse.dhelBahKern" ascii nocase
   $a4_advapi32dll = "h.dllhpi32hadva" ascii nocase
   $a5_advapires32dll = "hdllhs32.hpirehadva" ascii nocase
   $a6_gdi32dll = "hlh2.dlhgdi3" ascii nocase
   $a7_gdiplusdll = "hdllhlus.hgdip" ascii nocase
   $a8_win32ksys = "hysh2k.shwin3" ascii nocase
   $a9_user32dll = "hllh32.dhuser" ascii nocase
   $a10_comctl32dll = "h.dllhtl32hcomc" ascii nocase
   $a11_commdlgdll = "hdllhdlg.hcomm" ascii nocase
   $a12_comdlg32dll = "h.dllhlg32hcomd" ascii nocase
   $a13_commctrldll = "h.dllhctrlhcomm" ascii nocase
   $a14_shelldll = "hlhl.dlhshel" ascii nocase
   $a15_shell32dll = "hdllhl32.hshel" ascii nocase
   $a16_shlwapidll = "hdllhapi.hshlw" ascii nocase
   $a17_netapi32dll = "h.dllhpi32hneta" ascii nocase
   $a18_shdocvwdll = "hdllhcvw.hshdo" ascii nocase
   $a19_mshtmldll = "hllhml.dhmsht" ascii nocase
   $a20_urlmondll = "hllhon.dhurlm" ascii nocase
   $a21_iphlpapidll = "h.dllhpapihiphl" ascii nocase
   $a22_httpapidll = "hdllhapi.hhttp" ascii nocase
   $a23_msvbvm60dll = "h.dllhvm60hmsvb" ascii nocase
   $a24_shfolderdll = "h.dllhlderhshfo" ascii nocase
   $a25_OLE32DLL = "hLh2.DLhOLE3" ascii nocase
   $a26_wininetdll = "hdllhnet.hwini" ascii nocase
   $a27_wsock32dll = "hdllhk32.hwsoc" ascii nocase
 condition:
   filesize < 15MB
   and uint16be(0) == 0x4d5a
   and 1 of them
}
