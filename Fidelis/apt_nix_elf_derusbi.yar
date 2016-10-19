rule apt_nix_elf_derusbi
{
	meta: 
		author = "Fidelis Cybersecurity"
		reference = "https://www.fidelissecurity.com/resources/turbo-campaign-featuring-derusbi-64-bit-linux" 
	strings:
		$ = "LxMain"
		$ = "execve"
		$ = "kill"
		$ = "cp -a %s %s"
		$ = "%s &"
		$ = "dbus-daemon"
		$ = "--noprofile"
		$ = "--norc"
		$ = "TERM=vt100"
		$ = "/proc/%u/cmdline"
		$ = "loadso"
		$ = "/proc/self/exe"
		$ = "Proxy-Connection: Keep-Alive"
		$ = "Connection: Keep-Alive"
		$ = "CONNECT %s"
		$ = "HOST: %s:%d"
		$ = "User-Agent: Mozilla/4.0"
		$ = "Proxy-Authorization: Basic %s"
		$ = "Server: Apache"
		$ = "Proxy-Authenticate"
		$ = "gettimeofday"
		$ = "pthread_create"
		$ = "pthread_join"
		$ = "pthread_mutex_init"
		$ = "pthread_mutex_destroy"
		$ = "pthread_mutex_lock"
		$ = "getsockopt"
		$ = "socket"
		$ = "setsockopt"
		$ = "select"
		$ = "bind"
		$ = "shutdown"
		$ = "listen"
		$ = "opendir"
		$ = "readdir"
		$ = "closedir"
		$ = "rename"

	condition:
		(uint32(0) == 0x4464c457f) and (all of them)
}

