rule fopo
{
    meta:
        description = "Free Online PHP Obfuscator"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "b96a81b71d69a9bcb5a3f9f4edccb4a3c7373159d8eda874e053b23d361107f0"
        hash = "bbe5577639233b5a83c4caebf807c553430cab230f9a15ec519670dd8be6a924"
        hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"

    strings:
        $base64_decode = /\$[a-zA-Z0-9]+=\"\\(142|x62)\\(141|x61)\\(163|x73)\\(145|x65)\\(66|x36)\\(64|x34)\\(137|x5f)\\(144|x64)\\(145|x65)\\(143|x63)\\(157|x6f)\\(144|x64)\\(145|x65)\";@eval\(/

    condition:
        all of them
}
