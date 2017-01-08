rule adwind_201601
{
        meta:
                author = "@h3x2b <tracker _AT h3x.eu>"
                description = "Detects Adwind jar malware - 201601"
                //Check also:
                //https://github.com/Yara-Rules/rules/blob/master/malware/Adwind_JAR_PACKA.yar
                //https://github.com/Yara-Rules/rules/blob/master/malware/Adwind_JAR_PACKB.yar
                //https://github.com/kevthehermit/RATDecoders/blob/master/AlienSpy.py

        strings:
                //Jar
                $jar_00 = "META-INF/MANIFEST.MF"

                //Adwind classes
                $adwind_class_01 = "javas/MaIn.class"
                $adwind_class_02 = "javas/Encriiption.class"
                $adwind_class_03 = "javas/DecryptJarcITO.class"
                $adwind_class_04 = "javas/Cacao.class"
                $adwind_class_05 = "javas/SetupConfigFirst.class"
                $adwind_class_06 = "javas/DecryptJar.class"
                $adwind_class_07 = "javas/ClassFake.class"
                $adwind_class_08 = "main/Start.class"

                //Adwind config
                $adwind_cfg_01 = "components/linux.plsk"
                $adwind_cfg_02 = "components/mac.hwid"
                $adwind_cfg_03 = "components/manifest.ini"
                $adwind_cfg_04 = "components/logo.png"
                $adwind_cfg_05 = "components/picture.gif"
                $adwind_cfg_06 = "java/textito.isn"
                $adwind_cfg_07 = "klip/clip.mp4"
                $adwind_cfg_08 = "config/config.perl"
                $adwind_cfg_09 = "config/config.pl"
                $adwind_cfg_10 = "config/config.ini"
                $adwind_cfg_11 = "windows/windows.ini"

        condition:
                //Jar|ZIP file starts with "PK"
                uint16(0) == 0x4B50 and

                //Contains a MANIFEST metafile
                $jar_00 and

                //Contains any one of the Adwind classes
                any of ($adwind_class_*) and

                //Contains any of the Adwind key files
                any of ($adwind_cfg_*)
}
