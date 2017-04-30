rule PLUGX_RedLeaves
{
meta:
      author = "US-CERT Code Analysis Team"
      date = "03042017
      incident = "10118538"
      date = "2017/04/03"
      MD5_1 = "598FF82EA4FB52717ACAFB227C83D474"
      MD5_2 = "7D10708A518B26CC8C3CBFBAA224E032"
      MD5_3 = "AF406D35C77B1E0DF17F839E36BCE630"
      MD5_4 = "6EB9E889B091A5647F6095DCD4DE7C83"
      MD5_5 = "566291B277534B63EAFC938CDAAB8A399E41AF7D"
      info = "Detects specific RedLeaves and PlugX binaries"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
      $s0 = { 80343057403D2FD0010072F433C08BFF80343024403D2FD0010072F4 }
      $s1 = "C:\\Users\\user\\Desktop\\my_OK_2014\\bit9\\runsna\\Release\\runsna.pdb"
      $s2 = "d:\\work\\plug4.0(shellcode)"
      $s3 = "\\shellcode\\shellcode\\XSetting.h"
      $s4 = { 42AFF4276A45AA58474D4C4BE03D5B395566BEBCBDEDE9972872C5C4C5498228 }
      $s5 = { 8AD32AD002D180C23830140E413BCB7CEF6A006A006A00566A006A00 }
      $s6 = { EB055F8BC7EB05E8F6FFFFFF558BEC81ECC8040000535657 }
      $s7 = { 8A043233C932043983C10288043283F90A7CF242890D18AA00103BD37CE2891514AA00106A006A006A0056 }
      $s8 = { 293537675A402A333557B05E04D09CB05EB3ADA4A4A40ED0B7DAB7935F5B5B08 }
      $s9 = "RedLeavesCMDSimulatorMutex"
condition:
      $s0 or $s1 or $s2 and $s3 or $s4 or $s5 or $s6 or $s7 or $s8 or $s9
}
