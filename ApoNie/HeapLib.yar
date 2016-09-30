rule HeapLib
{
	meta:
		author = "adnan.shukor@gmail.com"
		description = "Detection of HeapLib which commonly used in heap spray related exploit"
		ref = "http://www.phreedom.org/research/heap-feng-shui/heap-feng-shui.html"
		cve = "NA"
		version = "1"
		impact = 3
		hide = false
	strings:
		$heaplib_1 = /\.ie\s?=\s?function\s?\(maxAlloc,/
		$heaplib_2 = /\.ie\.prototype\.round\s?=\s?function\s?\(num,\s?round\)/
		$heaplib_3 = /\.ie\.prototype\.hex\s?=\s?function\s?\(num,\s?width\)/
		$heaplib_4 = /\.ie\.prototype\.addr\s?=\s?function\s?\(addr\)/
		$heaplib_5 = /\.ie\.prototype\.allocOleaut32\s?=\s?function\s?\(arg,\s?tag\)/
		$heaplib_6 = /\.ie\.prototype\.freeOleaut32/

		$heaplib_7 = /\.maxAlloc\s?=\s?\(maxAlloc\s?\?\s?maxAlloc\s?:\s?65535\s?\)/
		$heaplib_8 = "return unescape(\"%u\" + this.hex(addr & 0xFFFF, 4) + \"%u\" + this.hex((addr >> 16) & 0xFFFF, 4))"
		$heaplib_9 = /\.(free|flush)Oleaut32\(/
		$heaplib_10 = "return this.heapBase + 0x688 + ((size+8)/8)*48"
		$heaplib_11 = /vtable\s?\+=\s?unescape\("%u0028%u0028"\)/
	condition:
		5 of them
}