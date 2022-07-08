rule Linux_Trojan_BPFDoor_1 {

    meta:
        Author = "Elastic Security"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        os = "Linux"
        arch = "x86"
        category_type = "Trojan"
        family = "BPFDoor"
        threat_name = "Linux.Trojan.BPFDoor"
        description = "Detects BPFDoor malware."
        reference_sample = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
    strings:
        $a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $a2 = "/sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d" ascii fullword
        $a3 = "avahi-daemon: chroot helper" ascii fullword
        $a4 = "/sbin/mingetty /dev/tty6" ascii fullword
        $a5 = "ttcompat" ascii fullword
    condition:
        all of them
}
