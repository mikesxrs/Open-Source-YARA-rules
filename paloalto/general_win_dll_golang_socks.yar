import "pe"

rule general_win_dll_golang_socks
{
    meta:
        author = "paloaltonetworks"
        date = "2022-03-13"
        description = "Highly suspicious GO DLL with proxy communication capabilities"
        reference = "https://unit42.paloaltonetworks.com/popping-eagle-malware/"
 
    condition:    
        general_win_golang_socks and 
        (pe.characteristics & pe.DLL) and pe.is_dll()
}

