rule lyceum_dotnet_http_backdoor
{
    meta:
        author = "CPR"
        reference = "https://research.checkpoint.com/2022/state-sponsored-attack-groups-capitalise-on-russia-ukraine-war-for-cyber-espionage/"
        hash1 = "1c444ebeba24dcba8628b7dfe5fec7c6"
        hash2 = "85ca334f87667bd7fa0c47ae6149353e"
        hash3 = "73bddd5f1a0847ae5f5d55e7d9c177f6"
        hash4 = "9fb86915db1b7c00f1a4587de4e052de"
        hash5 = "37fe608983d4b06a5549247f0e16bc11"
        hash6 = "5916e5189ef0050dfcc3cc19382d08d5"
    strings:
        $class1 = "Funcss"
        $class2 = "Constantss"
        $class3 = "Reqss"
        $class4 = "Screenss"
        $class5 = "Shll"
        $class6 = "test_A1"
        $class7 = "Uploadss"
        $class8 = "WebDL"
        $cnc_uri1 = "/upload" wide
        $cnc_uri2 = "/screenshot" wide
        $cnc_pattern_hex1 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 7b 30 7d 22 0d 0a 0d 0a}
        $cnc_pattern_hex2 = {6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 20 62 6f 75 6e 64 61 72 79 3d 7b 30 7d}
        $cnc_pattern_hex3 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 7b 30 7d 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 7b 31 7d 22 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 7b 32 7d 0d 0a 0d 0a}
        $constant1 = "FILE_DIR_SEPARATOR"
        $constant2 = "APPS_PARAMS_SEPARATOR"
        $constant3 = "TYPE_SENDTOKEN"
        $constant4 = "TYPE_DATA1"
        $constant5 = "TYPE_SEND_RESPONSE_IN_SOCKET"
        $constant6 = "TYPE_FILES_LIST"
        $constant7 = "TYPE_FILES_DELETE"
        $constant8 = "TYPE_FILES_RUN"
        $constant9 = "TYPE_FILES_UPLOAD_TO_SERVER"
        $constant10 = "TYPE_FILES_DELETE_FOLDER"
        $constant11 = "TYPE_FILES_CREATE_FOLDER"
        $constant12 = "TYPE_FILES_DOWNLOAD_URL"
        $constant13 = "TYPE_OPEN_CMD"
        $constant14 = "TYPE_CMD_RES"
        $constant15 = "TYPE_CLOSE_CMD"
        $constant16 = "TYPE_CMD_REQ"
        $constant17 = "TYPE_INSTALLED_APPS"
        $constant18 = "TYPE_SCREENSHOT"
        $constant19 = "_RG_APP_NAME_"
        $constant20 = "_RG_APP_VERSION_"
        $constant21 = "_RG_APP_DATE_"
        $constant22 = "_RG_APP_PUB_"
        $constant23 = "_RG_APP_SEP_"
        $constant24 = "_SC_EXT_"
    condition:
        uint16(0)==0x5a4d and (4 of ($class*) or 4 of ($cnc_*) or 4 of ($constant*))
}
