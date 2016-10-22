rule AnomaliLABS_Lazarus_wipe_file_routine {
 meta:
     author = "aaron shelmire"
     date = "2015 May 26"
     desc = “Yara sig to detect File Wiping routine of the Lazarus group”
     reference = "https://blog.anomali.com/evidence-of-stronger-ties-between-north-korea-and-swift-banking-attacks"
 strings:
     $rand_name_routine = { 99 B9 1A 00 00 00 F7 F9 80 C2 61 88 16 8A 46 01 46 84 C0 }
     /* imports for overwrite function */
     $imp_getTick = "GetTickCount"
     $imp_srand = "srand"
     $imp_CreateFile = "CreateFileA"
     $imp_SetFilePointer = "SetFilePointer"
     $imp_WriteFile = "WriteFile"
     $imp_FlushFileBuffers = "FlushFileBuffers"
     $imp_GetFileSizeEx = "GetFileSizeEx"
     $imp_CloseHandle = "CloseHandle"
     /* imports for rename function */
     $imp_strrchr = "strrchr"
     $imp_rand = "rand"
     $Move_File = "MoveFileA"
     $Move_FileEx = "MoveFileEx"
     $imp_RemoveDir = "RemoveDirectoryA"
     $imp_DeleteFile = "DeleteFileA"
     $imp_GetLastError = "GetLastError"
condition:
     $rand_name_routine and (11 of ($imp_*)) and ( 1 of ($Move_*))
}