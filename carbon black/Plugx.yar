import "pe"

rule bit9_ms15_093_plugx_dll_payload : TLPWHITE
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


rule bit9_ms15_093_plugx_dropper : TLPWHITE
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


