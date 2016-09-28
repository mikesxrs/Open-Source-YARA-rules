rule InceptionIOS {
    meta:
author = "Blue Coat Systems, Inc"
info = "Used by unknown APT actors: Inception"
reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    strings:
$a1 = "Developer/iOS/JohnClerk/"
$b1 = "SkypeUpdate"
$b2 = "/Syscat/"
$b3 = "WhatsAppUpdate"

    condition:
$a1 and any of ($b*)
}