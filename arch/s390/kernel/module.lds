SECTIONS {
	.text.indirect_jump : { *(.text.*_indirect_*) }
	.rela.orc_unwind : { *(.rela.orc_unwind*) }
	.orc_unwind_ip : { *(.orc_unwind_ip*) }
	.orc_unwind : { *(.orc_unwind*) }
}
