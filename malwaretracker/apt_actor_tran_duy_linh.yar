 rule apt_actor_tran_duy_linh
{
       meta:
         info = "author"
		 reference = "http://blog.malwaretracker.com/2013/06/tomato-garden-campaign-part-2-old-new.html"
       strings:
      $auth = { 4E 6F 72 6D 61 6C 2E 64 6F 74 6D 00 1E 00 00 00 10 00 00 00 54 72 61 6E 20 44 75 79 20 4C 69 6E 68 }

       condition:
               $auth
}
