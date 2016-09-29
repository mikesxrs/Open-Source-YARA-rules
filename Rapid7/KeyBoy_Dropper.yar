rule KeyBoy_Dropper  
{  
    meta:  
        author = "Rapid7 Labs"  
        reference = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"  
  
    strings:  
        $1 = "I am Admin"  
        $2 = "I am User"  
        $3 = "Run install success!"  
        $4 = "Service install success!"  
        $5 = "Something Error!"  
        $6 = "Not Configed, Exiting"  
  
    condition:  
        all of them  
}  