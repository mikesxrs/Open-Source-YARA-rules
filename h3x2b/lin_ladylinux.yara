rule ladylinux_go_malware: malware linux
{
meta:
	author = "@h3x2b <tracker@h3x.eu>"
	description = "Detects LadyLinux samples - 201609"

	//Check also:
	//http://vms.drweb.com/virus/?_is=1&i=8400823
	//https://www.youtube.com/watch?v=PRLOlY4IKeA
	//https://github.com/radareorg/r2con/raw/master/2016/talks/11-ReversingLinuxMalware/r2con_SergiMartinez_ReversingLinuxMalware.pdf
	//Samples:
	//d9a74531d24c76f3db95baed9ebf766a2bc0300d

strings:
	$m_01 = "/lady/src/attack/attack.go"
	$m_02 = "/lady/src/lady/config.go"
	$m_03 = "/lady/src/lady/main.go"

	$o_01 = "C:/Users/h/CloudStation/Projects/0/ly/lady/src/attack/attack.go"
	$o_02 = "C:/Users/h/CloudStation/Projects/0/ly/lady/src/lady/config.go"
	$o_03 = "C:/Users/h/CloudStation/Projects/0/ly/lady/src/lady/main.go"
	$o_04 = "C:/Users/h/CloudStation/Projects/0/ly/lady/src/st/struct.go"
	$o_05 = "C:/Users/h/CloudStation/Projects/0/ly/lady/src/attack/attack.go"
	$o_06 = "C:/Users/h/CloudStation/Projects/0/ly/lady/src/super/super.go"
	$o_07 = "C:/Users/h/CloudStation/Projects/0/ly/lady/src/redis/redis.go"
	$o_08 = "C:/Users/h/CloudStation/Projects/0/ly/lady/src/minerd/minerd.go"
	$o_09 = "C:/Users/h/CloudStation/Projects/0/ly/lady/src/ipip/ipip.go"
	$o_10 = "ly/lady/vendor/src/golang.org/x/crypto/ed25519/internal/edwards25519/edwards25519.go"
	$o_11 = "ly/lady/vendor/src/golang.org/x/crypto/ed25519/ed25519.go"
	$o_12 = "ly/lady/vendor/src/github.com/garyburd/redigo"
	$o_13 = "ly/lady/vendor/src/github.com/shirou/gopsutil"
	$o_14 = "ly/lady/vendor/src/github.com/parnurzeal/gorequest"
	$o_15 = "ly/lady/vendor/src/golang.org/x/net/publicsuffix"
	$o_16 = "ly/lady/vendor/src/github.com/moul/http2curl"
	$o_17 = "ly/lady/vendor/src/github.com/naoina/toml"
	$o_18 = "ly/lady/vendor/src/github.com/kardianos"
	$o_19 = "/tmp/__debuglady.log"


condition:
	//ELF magic
	uint32(0) == 0x464c457f and

	//Contains all mandatory strings
	all of ($m_*) and

	//Contains some optional strings
	15 of ($o_*)

}

