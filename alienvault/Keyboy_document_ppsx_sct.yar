rule keyboy_document_ppsx_sct

{

    meta:

       author = "AlienVault Labs"

       copyright = "Alienvault Inc. 2018"
       
       reference = "https://www.alienvault.com/blogs/labs-research/delivery-keyboy"

       license = "Apache License, Version 2.0"

       description = "Matches on compressed sub-file"

       sha256 = "831c3c40cc3fbc28b1ce1eca6bf278602c088f0580d6bdf324ef949c7d48a707"

       strings:

              $string_1 = "<vt:lpstr>script:http://"

              $string_2 = ".sct\" TargetMode=\"External\"/></Relationships>"

       condition:

        any of them

}
