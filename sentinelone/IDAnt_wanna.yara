import "elf"

rule IDAnt_wanna : antidissemble antianalysis
{
	meta:
		author = "Tim 'diff' Strazzere <diff@sentinelone.com><strazz@gmail.com>"
		reference = "https://sentinelone.com/blogs/breaking-and-evading/"\
		filetype = "elf"
		description = "Detect a misalligned program header which causes some analysis engines to fail"
		version = "1.0"
		date = "2015-12"
	condition:
		for any i in (0..elf.number_of_segments - 1) :(elf.segments[i].offset >= filesize) and elf.number_of_sections == 0 and elf.sh_entry_size == 0
}