rule rsa_modulus { 
meta:
 Author="NCCIC trusted 3rd party"
 reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-221A"
 Incident="10135536"
 Date = "2018/04/19"
 category = "hidden_cobra"
 family = "n/a"
 description = "n/a"
strings:
 $n = "bc9b75a31177587245305cd418b8df78652d1c03e9da0cfc910d6d38ee4191d40" 
condition:
 (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them
}
