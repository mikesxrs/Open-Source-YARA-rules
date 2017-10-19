rule ShellPhish 
{
 meta:
 reference = "https://windowsir.blogspot.com/2017/10/updates.html"
 strings:
        $birth_node = { 08 D4 0C 47 F8 73 C2 }
        $vol_id        = { 7E E4 BC 9C }
        $sid             = "2287413414-4262531481-1086768478" wide ascii
  
 condition:
  all of them
}
