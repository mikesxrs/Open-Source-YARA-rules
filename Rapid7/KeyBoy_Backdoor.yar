rule KeyBoy_Backdoor  
{  
    meta:  
        author = "Rapid7 Labs"  
        reference = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"  
  
    strings:  
        $1 = "$login$"  
        $2 = "$sysinfo$"  
        $3 = "$shell$"  
        $4 = "$fileManager$"  
        $5 = "$fileDownload$"  
        $6 = "$fileUpload$"  
  
    condition:  
        all of them  
}  