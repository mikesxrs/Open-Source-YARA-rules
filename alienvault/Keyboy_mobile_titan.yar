rule keyboy_mobile_titan

{

    meta:

       author = "AlienVault Labs"

       copyright = "Alienvault Inc. 2018"
       
       reference = "https://www.alienvault.com/blogs/labs-research/delivery-keyboy"

       license = "Apache License, Version 2.0"

       sha256 = "5acc64f814cc06db5e5cc56784607ddfa95e3e45170002a210c807857d48a1b0"

       strings:

              $string_1 = "titans.action.GLOBAL_ACTION"

              $string_2 = "titans.action.LOCATION_ACTION"

              $string_3 = "titans.action.PHONE_RECORD_ACTION"

       condition:

        all of them

}
