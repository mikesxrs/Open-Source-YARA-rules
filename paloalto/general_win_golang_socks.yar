import "pe"

rule general_win_golang_socks
{
    meta:
        author = "paloaltonetworks"
        date = "2022-03-13"
        description = "potentially unwanted GO application with proxy communication capabilities"
        reference = "https://unit42.paloaltonetworks.com/popping-eagle-malware/"
 
    strings:
        $go_name_1 = "main.go" nocase ascii // default go name for the “func main(){...}” in "package main”
        $go_name_2 = "eagle" nocase ascii
        $go_name_3 = "popo" nocase ascii
        $go_name_4 = "-Client-Dll/" nocase ascii
 
        $go_pkg_1 = "github.com/armon/go-socks5" nocase wide ascii
        $go_pkg_2 = "github.com/hashicorp/yamux" nocase wide ascii
        $go_pkg_3 = "github.com/fatedier/frp/vendor" wide ascii  
        $go_pkg_4 = "github.com/rofl0r/rocksocks5" wide ascii  
 
    condition:
        uint16(0) == 0x5a4d and 
        filesize < 7MB and
        (
            1 of ($go_name_*) and 
            2 of ($go_pkg_*)
        )
}

