import "pe"

rule plugx_VirtualProtect_3f : APT malware
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detects obfuscated strings as used in the DLL loading the PlugX payload. String: VirtualProtect"
	strings:
		$VirtualProtect_3f_00 = { 69 56 4d 4b 4a 5e 53 6f 4d 50 4b 5a 5c 4b }
		$VirtualProtect_3f_01 = { 6b 58 4f 4d 4c 60 55 71 4f 52 4d 5c 5e 4d }
		$VirtualProtect_3f_02 = { 6d 5a 51 4f 4e 62 57 73 51 54 4f 5e 60 4f }
		$VirtualProtect_3f_03 = { 6f 5c 53 51 50 64 59 75 53 56 51 60 62 51 }
		$VirtualProtect_3f_04 = { 71 5e 55 53 52 66 5b 77 55 58 53 62 64 53 }
		$VirtualProtect_3f_05 = { 73 60 57 55 54 68 5d 79 57 5a 55 64 66 55 }
		$VirtualProtect_3f_06 = { 75 62 59 57 56 6a 5f 7b 59 5c 57 66 68 57 }
		$VirtualProtect_3f_07 = { 77 64 5b 59 58 6c 61 7d 5b 5e 59 68 6a 59 }
		$VirtualProtect_3f_08 = { 79 66 5d 5b 5a 6e 63 7f 5d 60 5b 6a 6c 5b }
		$VirtualProtect_3f_09 = { 7b 68 5f 5d 5c 70 65 81 5f 62 5d 6c 6e 5d }
		$VirtualProtect_3f_0a = { 7d 6a 61 5f 5e 72 67 83 61 64 5f 6e 70 5f }
		$VirtualProtect_3f_0b = { 7f 6c 63 61 60 74 69 85 63 66 61 70 72 61 }
		$VirtualProtect_3f_0c = { 81 6e 65 63 62 76 6b 87 65 68 63 72 74 63 }
		$VirtualProtect_3f_0d = { 83 70 67 65 64 78 6d 89 67 6a 65 74 76 65 }
		$VirtualProtect_3f_0e = { 85 72 69 67 66 7a 6f 8b 69 6c 67 76 78 67 }
		$VirtualProtect_3f_0f = { 87 74 6b 69 68 7c 71 8d 6b 6e 69 78 7a 69 }
		$VirtualProtect_3f_10 = { 89 76 6d 6b 6a 7e 73 8f 6d 70 6b 7a 7c 6b }
		$VirtualProtect_3f_11 = { 8b 78 6f 6d 6c 80 75 11 6f 72 6d 7c 7e 6d }
		$VirtualProtect_3f_12 = { 8d 7a 71 6f 6e 82 77 13 71 74 6f 7e 80 6f }
		$VirtualProtect_3f_13 = { 8f 7c 73 71 70 84 79 15 73 76 71 80 82 71 }
		$VirtualProtect_3f_14 = { 91 7e 75 73 72 86 7b 17 75 78 73 82 84 73 }
		$VirtualProtect_3f_15 = { 93 80 77 75 74 88 7d 19 77 7a 75 84 86 75 }
		$VirtualProtect_3f_16 = { 95 82 79 77 76 8a 7f 1b 79 7c 77 86 88 77 }
		$VirtualProtect_3f_17 = { 17 84 7b 79 78 8c 81 1d 7b 7e 79 88 8a 79 }
		$VirtualProtect_3f_18 = { 19 86 7d 7b 7a 8e 83 1f 7d 80 7b 8a 8c 7b }
		$VirtualProtect_3f_19 = { 1b 88 7f 7d 7c 90 85 21 7f 82 7d 8c 8e 7d }
		$VirtualProtect_3f_1a = { 1d 8a 81 7f 7e 92 87 23 81 84 7f 8e 90 7f }
		$VirtualProtect_3f_1b = { 1f 8c 83 81 80 94 89 25 83 86 81 90 92 81 }
		$VirtualProtect_3f_1c = { 21 8e 85 83 82 96 8b 27 85 88 83 92 94 83 }
		$VirtualProtect_3f_1d = { 23 90 87 85 84 98 8d 29 87 8a 85 94 96 85 }
		$VirtualProtect_3f_1e = { 25 92 89 87 86 9a 8f 2b 89 8c 87 96 98 87 }
		$VirtualProtect_3f_1f = { 27 94 8b 89 88 9c 91 2d 8b 8e 89 98 9a 89 }
		$VirtualProtect_3f_20 = { 29 96 8d 8b 8a 9e 93 2f 8d 90 8b 9a 9c 8b }
		$VirtualProtect_3f_21 = { 2b 98 8f 8d 8c a0 95 31 8f 92 8d 9c 9e 8d }
		$VirtualProtect_3f_22 = { 2d 9a 91 8f 8e 22 97 33 91 94 8f 9e a0 8f }
		$VirtualProtect_3f_23 = { 2f 9c 93 91 90 24 99 35 93 96 91 a0 a2 91 }
		$VirtualProtect_3f_24 = { 31 9e 95 93 92 26 9b 37 95 98 93 a2 24 93 }
		$VirtualProtect_3f_25 = { 33 a0 97 95 94 28 9d 39 97 9a 95 a4 26 95 }
		$VirtualProtect_3f_26 = { 35 a2 99 97 96 2a 9f 3b 99 9c 97 26 28 97 }
		$VirtualProtect_3f_27 = { 37 a4 9b 99 98 2c a1 3d 9b 9e 99 28 2a 99 }
		$VirtualProtect_3f_28 = { 39 a6 9d 9b 9a 2e a3 3f 9d a0 9b 2a 2c 9b }
		$VirtualProtect_3f_29 = { 3b a8 9f 9d 9c 30 a5 41 9f a2 9d 2c 2e 9d }
		$VirtualProtect_3f_2a = { 3d 2a a1 9f 9e 32 a7 43 a1 a4 9f 2e 30 9f }
		$VirtualProtect_3f_2b = { 3f 2c a3 a1 a0 34 a9 45 a3 a6 a1 30 32 a1 }
		$VirtualProtect_3f_2c = { 41 2e a5 a3 a2 36 ab 47 a5 a8 a3 32 34 a3 }
		$VirtualProtect_3f_2d = { 43 30 a7 a5 a4 38 2d 49 a7 aa a5 34 36 a5 }
		$VirtualProtect_3f_2e = { 45 32 a9 a7 a6 3a 2f 4b a9 ac a7 36 38 a7 }
		$VirtualProtect_3f_2f = { 47 34 ab a9 a8 3c 31 4d ab ae a9 38 3a a9 }
		$VirtualProtect_3f_30 = { 49 36 ad ab aa 3e 33 4f ad 30 ab 3a 3c ab }
		$VirtualProtect_3f_31 = { 4b 38 af ad ac 40 35 51 af 32 ad 3c 3e ad }
		$VirtualProtect_3f_32 = { 4d 3a b1 af ae 42 37 53 b1 34 af 3e 40 af }
		$VirtualProtect_3f_33 = { 4f 3c 33 b1 b0 44 39 55 33 36 b1 40 42 b1 }
		$VirtualProtect_3f_34 = { 51 3e 35 b3 b2 46 3b 57 35 38 b3 42 44 b3 }
		$VirtualProtect_3f_35 = { 53 40 37 35 b4 48 3d 59 37 3a 35 44 46 35 }
		$VirtualProtect_3f_36 = { 55 42 39 37 36 4a 3f 5b 39 3c 37 46 48 37 }
		$VirtualProtect_3f_37 = { 57 44 3b 39 38 4c 41 5d 3b 3e 39 48 4a 39 }
		$VirtualProtect_3f_38 = { 59 46 3d 3b 3a 4e 43 5f 3d 40 3b 4a 4c 3b }
		$VirtualProtect_3f_39 = { 5b 48 3f 3d 3c 50 45 61 3f 42 3d 4c 4e 3d }
		$VirtualProtect_3f_3a = { 5d 4a 41 3f 3e 52 47 63 41 44 3f 4e 50 3f }
		$VirtualProtect_3f_3b = { 5f 4c 43 41 40 54 49 65 43 46 41 50 52 41 }
		$VirtualProtect_3f_3c = { 61 4e 45 43 42 56 4b 67 45 48 43 52 54 43 }
		$VirtualProtect_3f_3d = { 63 50 47 45 44 58 4d 69 47 4a 45 54 56 45 }
		$VirtualProtect_3f_3e = { 65 52 49 47 46 5a 4f 6b 49 4c 47 56 58 47 }
		$VirtualProtect_3f_3f = { 67 54 4b 49 48 5c 51 6d 4b 4e 49 58 5a 49 }

	condition:
		//File starts with MZ
		uint16(0) == 0x5a4d and
		1 of them
}


rule plugx_advapi32_dll_3f : APT malware
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detects obfuscated strings as used in the DLL loading the PlugX payload. String: advapi32.dll"
	strings:
		$advapi32_dll_3f_00 = { 5e 5b 49 5e 4f 56 0c 0d 11 5b 53 53 }
		$advapi32_dll_3f_01 = { 60 5d 4b 60 51 58 0e 0f 13 5d 55 55 }
		$advapi32_dll_3f_02 = { 62 5f 4d 62 53 5a 10 11 15 5f 57 57 }
		$advapi32_dll_3f_03 = { 64 61 4f 64 55 5c 12 13 17 61 59 59 }
		$advapi32_dll_3f_04 = { 66 63 51 66 57 5e 14 15 19 63 5b 5b }
		$advapi32_dll_3f_05 = { 68 65 53 68 59 60 16 17 1b 65 5d 5d }
		$advapi32_dll_3f_06 = { 6a 67 55 6a 5b 62 18 19 1d 67 5f 5f }
		$advapi32_dll_3f_07 = { 6c 69 57 6c 5d 64 1a 1b 1f 69 61 61 }
		$advapi32_dll_3f_08 = { 6e 6b 59 6e 5f 66 1c 1d 21 6b 63 63 }
		$advapi32_dll_3f_09 = { 70 6d 5b 70 61 68 1e 1f 23 6d 65 65 }
		$advapi32_dll_3f_0a = { 72 6f 5d 72 63 6a 20 21 25 6f 67 67 }
		$advapi32_dll_3f_0b = { 74 71 5f 74 65 6c 22 23 27 71 69 69 }
		$advapi32_dll_3f_0c = { 76 73 61 76 67 6e 24 25 29 73 6b 6b }
		$advapi32_dll_3f_0d = { 78 75 63 78 69 70 26 27 2b 75 6d 6d }
		$advapi32_dll_3f_0e = { 7a 77 65 7a 6b 72 28 29 2d 77 6f 6f }
		$advapi32_dll_3f_0f = { 7c 79 67 7c 6d 74 2a 2b 2f 79 71 71 }
		$advapi32_dll_3f_10 = { 7e 7b 69 7e 6f 76 2c 2d 31 7b 73 73 }
		$advapi32_dll_3f_11 = { 80 7d 6b 80 71 78 2e 2f 33 7d 75 75 }
		$advapi32_dll_3f_12 = { 82 7f 6d 82 73 7a 30 31 35 7f 77 77 }
		$advapi32_dll_3f_13 = { 84 81 6f 84 75 7c 32 33 37 81 79 79 }
		$advapi32_dll_3f_14 = { 86 83 71 86 77 7e 34 35 39 83 7b 7b }
		$advapi32_dll_3f_15 = { 88 85 73 88 79 80 36 37 3b 85 7d 7d }
		$advapi32_dll_3f_16 = { 8a 87 75 8a 7b 82 38 39 3d 87 7f 7f }
		$advapi32_dll_3f_17 = { 8c 89 77 8c 7d 84 3a 3b 3f 89 81 81 }
		$advapi32_dll_3f_18 = { 8e 8b 79 8e 7f 86 3c 3d 41 8b 83 83 }
		$advapi32_dll_3f_19 = { 90 8d 7b 90 81 88 3e 3f 43 8d 85 85 }
		$advapi32_dll_3f_1a = { 92 8f 7d 92 83 8a 40 41 45 8f 87 87 }
		$advapi32_dll_3f_1b = { 94 91 7f 94 85 8c 42 43 47 91 89 89 }
		$advapi32_dll_3f_1c = { 96 93 81 96 87 8e 44 45 49 93 8b 8b }
		$advapi32_dll_3f_1d = { 98 95 83 98 89 90 46 47 4b 95 8d 8d }
		$advapi32_dll_3f_1e = { 9a 97 85 9a 8b 92 48 49 4d 97 8f 8f }
		$advapi32_dll_3f_1f = { 9c 99 87 9c 8d 94 4a 4b 4f 99 91 91 }
		$advapi32_dll_3f_20 = { 9e 9b 89 9e 8f 96 4c 4d 51 9b 93 93 }
		$advapi32_dll_3f_21 = { a0 9d 8b a0 91 98 4e 4f 53 9d 95 95 }
		$advapi32_dll_3f_22 = { 22 9f 8d 22 93 9a 50 51 55 9f 97 97 }
		$advapi32_dll_3f_23 = { 24 a1 8f 24 95 9c 52 53 57 a1 99 99 }
		$advapi32_dll_3f_24 = { 26 a3 91 26 97 9e 54 55 59 a3 9b 9b }
		$advapi32_dll_3f_25 = { 28 25 93 28 99 a0 56 57 5b 25 9d 9d }
		$advapi32_dll_3f_26 = { 2a 27 95 2a 9b a2 58 59 5d 27 9f 9f }
		$advapi32_dll_3f_27 = { 2c 29 97 2c 9d a4 5a 5b 5f 29 a1 a1 }
		$advapi32_dll_3f_28 = { 2e 2b 99 2e 9f a6 5c 5d 61 2b a3 a3 }
		$advapi32_dll_3f_29 = { 30 2d 9b 30 a1 a8 5e 5f 63 2d a5 a5 }
		$advapi32_dll_3f_2a = { 32 2f 9d 32 a3 2a 60 61 65 2f a7 a7 }
		$advapi32_dll_3f_2b = { 34 31 9f 34 a5 2c 62 63 67 31 a9 a9 }
		$advapi32_dll_3f_2c = { 36 33 a1 36 a7 2e 64 65 69 33 ab ab }
		$advapi32_dll_3f_2d = { 38 35 a3 38 a9 30 66 67 6b 35 2d 2d }
		$advapi32_dll_3f_2e = { 3a 37 a5 3a ab 32 68 69 6d 37 2f 2f }
		$advapi32_dll_3f_2f = { 3c 39 a7 3c ad 34 6a 6b ef 39 31 31 }
		$advapi32_dll_3f_30 = { 3e 3b a9 3e af 36 6c 6d f1 3b 33 33 }
		$advapi32_dll_3f_31 = { 40 3d ab 40 31 38 6e 6f f3 3d 35 35 }
		$advapi32_dll_3f_32 = { 42 3f ad 42 33 3a 70 71 f5 3f 37 37 }
		$advapi32_dll_3f_33 = { 44 41 af 44 35 3c 72 f3 f7 41 39 39 }
		$advapi32_dll_3f_34 = { 46 43 b1 46 37 3e f4 f5 f9 43 3b 3b }
		$advapi32_dll_3f_35 = { 48 45 b3 48 39 40 f6 f7 fb 45 3d 3d }
		$advapi32_dll_3f_36 = { 4a 47 b5 4a 3b 42 f8 f9 fd 47 3f 3f }
		$advapi32_dll_3f_37 = { 4c 49 37 4c 3d 44 fa fb ff 49 41 41 }
		$advapi32_dll_3f_38 = { 4e 4b 39 4e 3f 46 fc fd 01 4b 43 43 }
		$advapi32_dll_3f_39 = { 50 4d 3b 50 41 48 fe ff 03 4d 45 45 }
		$advapi32_dll_3f_3a = { 52 4f 3d 52 43 4a 00 01 05 4f 47 47 }
		$advapi32_dll_3f_3b = { 54 51 3f 54 45 4c 02 03 07 51 49 49 }
		$advapi32_dll_3f_3c = { 56 53 41 56 47 4e 04 05 09 53 4b 4b }
		$advapi32_dll_3f_3d = { 58 55 43 58 49 50 06 07 0b 55 4d 4d }
		$advapi32_dll_3f_3e = { 5a 57 45 5a 4b 52 08 09 0d 57 4f 4f }
		$advapi32_dll_3f_3f = { 5c 59 47 5c 4d 54 0a 0b 0f 59 51 51 }

	condition:
		//File starts with MZ
		uint16(0) == 0x5a4d and
		1 of them
}

rule plugx_GetModuleHandleA_3f : APT malware
{
meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detects obfuscated strings as used in the DLL loading the PlugX payload. String: GetModuleHandleA"

strings:
		$GetModuleHandleA_3f_00 = { 78 5a 4b 72 50 5b 4a 53 5a 77 5e 51 5b 53 5a 7e }
		$GetModuleHandleA_3f_01 = { 7a 5c 4d 74 52 5d 4c 55 5c 79 60 53 5d 55 5c 80 }
		$GetModuleHandleA_3f_02 = { 7c 5e 4f 76 54 5f 4e 57 5e 7b 62 55 5f 57 5e 02 }
		$GetModuleHandleA_3f_03 = { 7e 60 51 78 56 61 50 59 60 7d 64 57 61 59 60 04 }
		$GetModuleHandleA_3f_04 = { 80 62 53 7a 58 63 52 5b 62 7f 66 59 63 5b 62 06 }
		$GetModuleHandleA_3f_05 = { 82 64 55 7c 5a 65 54 5d 64 81 68 5b 65 5d 64 08 }
		$GetModuleHandleA_3f_06 = { 84 66 57 7e 5c 67 56 5f 66 83 6a 5d 67 5f 66 0a }
		$GetModuleHandleA_3f_07 = { 86 68 59 80 5e 69 58 61 68 85 6c 5f 69 61 68 0c }
		$GetModuleHandleA_3f_08 = { 08 6a 5b 82 60 6b 5a 63 6a 87 6e 61 6b 63 6a 0e }
		$GetModuleHandleA_3f_09 = { 0a 6c 5d 84 62 6d 5c 65 6c 09 70 63 6d 65 6c 10 }
		$GetModuleHandleA_3f_0a = { 0c 6e 5f 86 64 6f 5e 67 6e 0b 72 65 6f 67 6e 12 }
		$GetModuleHandleA_3f_0b = { 0e 70 61 88 66 71 60 69 70 0d 74 67 71 69 70 14 }
		$GetModuleHandleA_3f_0c = { 10 72 63 8a 68 73 62 6b 72 0f 76 69 73 6b 72 16 }
		$GetModuleHandleA_3f_0d = { 12 74 65 8c 6a 75 64 6d 74 11 78 6b 75 6d 74 18 }
		$GetModuleHandleA_3f_0e = { 14 76 67 0e 6c 77 66 6f 76 13 7a 6d 77 6f 76 1a }
		$GetModuleHandleA_3f_0f = { 16 78 69 10 6e 79 68 71 78 15 7c 6f 79 71 78 1c }
		$GetModuleHandleA_3f_10 = { 18 7a 6b 12 70 7b 6a 73 7a 17 7e 71 7b 73 7a 1e }
		$GetModuleHandleA_3f_11 = { 1a 7c 6d 14 72 7d 6c 75 7c 19 80 73 7d 75 7c 20 }
		$GetModuleHandleA_3f_12 = { 1c 7e 6f 16 74 7f 6e 77 7e 1b 82 75 7f 77 7e 22 }
		$GetModuleHandleA_3f_13 = { 1e 80 71 18 76 81 70 79 80 1d 84 77 81 79 80 24 }
		$GetModuleHandleA_3f_14 = { 20 82 73 1a 78 83 72 7b 82 1f 86 79 83 7b 82 26 }
		$GetModuleHandleA_3f_15 = { 22 84 75 1c 7a 85 74 7d 84 21 88 7b 85 7d 84 28 }
		$GetModuleHandleA_3f_16 = { 24 86 77 1e 7c 87 76 7f 86 23 8a 7d 87 7f 86 2a }
		$GetModuleHandleA_3f_17 = { 26 88 79 20 7e 89 78 81 88 25 8c 7f 89 81 88 2c }
		$GetModuleHandleA_3f_18 = { 28 8a 7b 22 80 8b 7a 83 8a 27 8e 81 8b 83 8a 2e }
		$GetModuleHandleA_3f_19 = { 2a 8c 7d 24 82 8d 7c 85 8c 29 90 83 8d 85 8c 30 }
		$GetModuleHandleA_3f_1a = { 2c 8e 7f 26 84 8f 7e 87 8e 2b 92 85 8f 87 8e 32 }
		$GetModuleHandleA_3f_1b = { 2e 90 81 28 86 91 80 89 90 2d 94 87 91 89 90 34 }
		$GetModuleHandleA_3f_1c = { 30 92 83 2a 88 93 82 8b 92 2f 96 89 93 8b 92 36 }
		$GetModuleHandleA_3f_1d = { 32 94 85 2c 8a 95 84 8d 94 31 98 8b 95 8d 94 38 }
		$GetModuleHandleA_3f_1e = { 34 96 87 2e 8c 97 86 8f 96 33 9a 8d 97 8f 96 3a }
		$GetModuleHandleA_3f_1f = { 36 98 89 30 8e 99 88 91 98 35 9c 8f 99 91 98 3c }
		$GetModuleHandleA_3f_20 = { 38 9a 8b 32 90 9b 8a 93 9a 37 9e 91 9b 93 9a 3e }
		$GetModuleHandleA_3f_21 = { 3a 9c 8d 34 92 9d 8c 95 9c 39 a0 93 9d 95 9c 40 }
		$GetModuleHandleA_3f_22 = { 3c 9e 8f 36 94 9f 8e 97 9e 3b 22 95 9f 97 9e 42 }
		$GetModuleHandleA_3f_23 = { 3e a0 91 38 96 a1 90 99 a0 3d 24 97 a1 99 a0 44 }
		$GetModuleHandleA_3f_24 = { 40 a2 93 3a 98 a3 92 9b a2 3f 26 99 a3 9b a2 46 }
		$GetModuleHandleA_3f_25 = { 42 a4 95 3c 9a 25 94 9d a4 41 28 9b 25 9d a4 48 }
		$GetModuleHandleA_3f_26 = { 44 26 97 3e 9c 27 96 9f 26 43 2a 9d 27 9f 26 4a }
		$GetModuleHandleA_3f_27 = { 46 28 99 40 9e 29 98 a1 28 45 2c 9f 29 a1 28 4c }
		$GetModuleHandleA_3f_28 = { 48 2a 9b 42 a0 2b 9a a3 2a 47 2e a1 2b a3 2a 4e }
		$GetModuleHandleA_3f_29 = { 4a 2c 9d 44 a2 2d 9c a5 2c 49 30 a3 2d a5 2c 50 }
		$GetModuleHandleA_3f_2a = { 4c 2e 9f 46 a4 2f 9e a7 2e 4b 32 a5 2f a7 2e 52 }
		$GetModuleHandleA_3f_2b = { 4e 30 a1 48 a6 31 a0 a9 30 4d 34 a7 31 a9 30 54 }
		$GetModuleHandleA_3f_2c = { 50 32 a3 4a a8 33 a2 ab 32 4f 36 a9 33 ab 32 56 }
		$GetModuleHandleA_3f_2d = { 52 34 a5 4c aa 35 a4 2d 34 51 38 ab 35 2d 34 58 }
		$GetModuleHandleA_3f_2e = { 54 36 a7 4e ac 37 a6 2f 36 53 3a ad 37 2f 36 5a }
		$GetModuleHandleA_3f_2f = { 56 38 a9 50 ae 39 a8 31 38 55 3c 2f 39 31 38 5c }
		$GetModuleHandleA_3f_30 = { 58 3a ab 52 30 3b aa 33 3a 57 3e 31 3b 33 3a 5e }
		$GetModuleHandleA_3f_31 = { 5a 3c ad 54 32 3d ac 35 3c 59 40 33 3d 35 3c 60 }
		$GetModuleHandleA_3f_32 = { 5c 3e af 56 34 3f ae 37 3e 5b 42 35 3f 37 3e 62 }
		$GetModuleHandleA_3f_33 = { 5e 40 b1 58 36 41 b0 39 40 5d 44 37 41 39 40 64 }
		$GetModuleHandleA_3f_34 = { 60 42 b3 5a 38 43 b2 3b 42 5f 46 39 43 3b 42 66 }
		$GetModuleHandleA_3f_35 = { 62 44 35 5c 3a 45 b4 3d 44 61 48 3b 45 3d 44 68 }
		$GetModuleHandleA_3f_36 = { 64 46 37 5e 3c 47 36 3f 46 63 4a 3d 47 3f 46 6a }
		$GetModuleHandleA_3f_37 = { 66 48 39 60 3e 49 38 41 48 65 4c 3f 49 41 48 6c }
		$GetModuleHandleA_3f_38 = { 68 4a 3b 62 40 4b 3a 43 4a 67 4e 41 4b 43 4a 6e }
		$GetModuleHandleA_3f_39 = { 6a 4c 3d 64 42 4d 3c 45 4c 69 50 43 4d 45 4c 70 }
		$GetModuleHandleA_3f_3a = { 6c 4e 3f 66 44 4f 3e 47 4e 6b 52 45 4f 47 4e 72 }
		$GetModuleHandleA_3f_3b = { 6e 50 41 68 46 51 40 49 50 6d 54 47 51 49 50 74 }
		$GetModuleHandleA_3f_3c = { 70 52 43 6a 48 53 42 4b 52 6f 56 49 53 4b 52 76 }
		$GetModuleHandleA_3f_3d = { 72 54 45 6c 4a 55 44 4d 54 71 58 4b 55 4d 54 78 }
		$GetModuleHandleA_3f_3e = { 74 56 47 6e 4c 57 46 4f 56 73 5a 4d 57 4f 56 7a }
		$GetModuleHandleA_3f_3f = { 76 58 49 70 4e 59 48 51 58 75 5c 4f 59 51 58 7c }

	condition:
		//File starts with MZ
		uint16(0) == 0x5a4d and
		1 of them
}


rule ms15_093_plugx_dll_payload : APT malware
{
	meta:
		author = "rnolen@bit9.com"
		date = "8.26.2015"
		description = "Find a specific plugx variant DLL payload"
		hash1 = "20d88b0fa34d3d79629cb602f08a1145008a75215fe2c91a3b3171287adc4c3d"
	strings:
		$datfile = "nvdisps_user.dat"
		$dllfile = "nvdisps.dll"
		$mutex	= "nvdisps_event"
	condition:
		3 of ($datfile,$dllfile,$mutex) and pe.exports("ShadowPlay")
}


rule ms15_093_plugx_dropper : APT malware
{
	meta:
		author = "rnolen@bit9.com"
		date = "8.26.2015"
		description = "Find a specific plugx variant dropper"
		hash1 = "61900fb9841a4d6d14e990163ea575694e684beaf912f50989b0013a9634196f"
		hash2 = "71b201a5a7dfdbe91c0a7783f845b71d066c62014b944f488de5aec6272f907c"
		hash3 = "56ec1ccab98c1ed67a0095b7ec8e6b17b12da3e00d357274fa37ec63ec724c07"
		hash4 = "c437465db42268332543fbf6fd6a560ca010f19e0fd56562fb83fb704824b371"
	strings:
		$datfile = "nvdisps_user.dat"
		$dllfile = "nvdisps.dll"
		$rundll32 = "Rundll32.exe"
		$winhlp32 = "\\winhlp32.exe"
		$shellout = "ShadowPlay 84"
	condition:
		5 of ($datfile,$dllfile,$rundll32,$winhlp32,$shellout)
}


import "cuckoo"

rule plugx_cuckoo_servers : APT
{
	meta:
		description = "Detect plugx samples based on the domain used"
		author = "@h3x2b <tracker _AT h3x.eu>"

	condition:
		cuckoo.network.http_request(/.*licdn.us/) or
		cuckoo.network.http_request(/.*voanews.hk/) or 
		cuckoo.network.http_request(/.*nhknews.hk/) or 
		cuckoo.network.http_request(/.*vancouversun.us/) or
		cuckoo.network.http_request(/.*yomiuri.us/) or
		cuckoo.network.http_request(/.*hnn.hk/)
}

rule plugx_cuckoo_registry : APT
{
	meta:
		description = "Detect plugx samples based on the registry used"
		author = "@h3x2b <tracker _AT h3x.eu>"

	condition:
		cuckoo.registry.key_access(/\\SOFTWARE\\BINARY\\.*/) or 
		cuckoo.registry.key_access(/\\Software\\BINARY\\.*/) 
}

rule plugx_c2_communication : APT
{
	meta:
		description = "Match the DZKS....DZJS C2 string"
		author = "@h3x2b <tracker _AT h3x.eu>"

	strings:
		$s1 = /DZKS[A-Z]*DZJS/

	condition:
		any of them

}

rule plugx_loader_apphelp : APT
{
	meta:
		description = "Identify the PlugX side loader used to trojan legit software like KMPlayer"
		author = "@h3x2b <tracker _AT h3x.eu>"

	strings:
		$yes_s1 = "RtlUnwind"
		$yes_s2 = "LoadLibraryA"
		$no_s1 = "ApphelpUpdateCacheEntry"

	condition:
		// file_type contains "pedll"
                uint16(0) == 0x5a4d
		and pe.characteristics & pe.DLL

		and all of ( $yes_* )
		and not $no_s1

		//and file_name contains "apphelp.dll"
}

