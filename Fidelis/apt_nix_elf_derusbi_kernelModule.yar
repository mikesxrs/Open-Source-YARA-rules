rule apt_nix_elf_derusbi_kernelModule
{
	meta: 
		author = "Fidelis Cybersecurity"
		reference = "https://www.fidelissecurity.com/resources/turbo-campaign-featuring-derusbi-64-bit-linux" 
	strings:
		$ = "__this_module"   
		$ = "init_module"      
		$ = "unhide_pid"       
		$ = "is_hidden_pid"    
		$ = "clear_hidden_pid" 
		$ = "hide_pid"
		$ = "license"
		$ = "description"
		$ = "srcversion="
		$ = "depends="
		$ = "vermagic="
		$ = "current_task"
		$ = "sock_release"
		$ = "module_layout"
		$ = "init_uts_ns"
		$ = "init_net"
		$ = "init_task"
		$ = "filp_open"
		$ = "__netlink_kernel_create"
		$ = "kfree_skb"

	condition:
		(uint32(0) == 0x4464c457f) and (all of them)
}
