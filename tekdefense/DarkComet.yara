rule DarkComet_Config_Artifacts_Memory

{   

     meta:

           Description = "Looks for configuration artifacts from DarkComet. Works with memory dump and unpacked samples."

           filetype = "MemoryDump"         

           Author = "Ian Ahl @TekDefese"

           Date = "12-19-2013"

           reference = "http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html"

     strings:

           $s0 = "GENCODE={" ascii

           $s1 = "MELT={" ascii

           $s2 = "COMBOPATH={" ascii

           $s3 = "NETDATA={" ascii

           $s4 = "PERSINST={" ascii

     condition:

           2 of them

}

 

rule DarkComet_Default_Mutex_Memory

{   

     meta:

           Description = "Looks for default DarkComet mutexs"

           filetype = "MemoryDump"              

           Author = "Ian Ahl @TekDefese"

           Date = "12-20-2013"

           reference = "http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html"


     strings:

           $s = "DC_MUTEX-" ascii nocase

     condition:

           any of them

}

 

rule DarkComet_Keylogs_Memory

{   

     meta:

           Description = "Looks for key log artifacts"

           filetype = "MemoryDump"              

           Author = "Ian Ahl @TekDefese"

           Date = "12-20-2013"

           reference = "http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html"


     strings:

           $s0 = "[<-]"

           $s1 = ":: Clipboard Change :"

           $s2 = "[LEFT]"

           $s4 = "[RIGHT]"

           $s5 = "[UP]"

           $s6 = "[DOWN]"

           $s7 = "[DEL]"

           $s8 = /::.{1,100}\(\d{1,2}:\d{1,2}:\d{1,2}\s\w{2}\)/  

     condition:

           any of them

}