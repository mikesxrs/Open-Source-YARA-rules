private rule PubSabCode : PubSab Family 
{
    meta:
        description = "PubSab code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $decrypt = { 6B 45 E4 37 89 CA 29 C2 89 55 E4 }
        
    condition:
        any of them
}

private rule PubSabStrings : PubSab Family
{
    meta:
        description = "PubSab Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "_deamon_init"
        $ = "com.apple.PubSabAgent"
        $ = "/tmp/screen.jpeg"
       
    condition:
        any of them
}

rule PubSab : Family
{
    meta:
        description = "PubSab"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        PubSabCode or PubSabStrings
}