rule angler_ek_checkpoint
{
	meta:
		description = "Angler EK Exploit Kit - Checkpoint Detection"
	strings:
		$a = "Jul 2039" nocase
		$b = "Jul 2040" nocase
	condition:
		any of them
}