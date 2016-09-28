rule InceptionBlackberry {
    meta:
author = "Blue Coat Systems, Inc"
info = "Used by unknown APT actors: Inception"
reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    strings:
$a1 = "POSTALCODE:"
$a2 = "SecurityCategory:"
$a3 = "amount of free flash:"
$a4 = "$071|'1'|:"
$b1 = "God_Save_The_Queen"
$b2 = "UrlBlog"

    condition:
all of ($a*) or all of ($b*)
}