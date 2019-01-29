#ifndef _ASM_S390_UNWIND_HINTS_H
#define _ASM_S390_UNWIND_HINTS_H

#ifdef __ASSEMBLY__

	.macro UNWIND_HINT sp_offset=0 sp_reg=255 sp_ptregs=0 ra_reg=255 clear=1 skip=0
#ifdef CONFIG_STACK_VALIDATION
.Lunwind_hint_ip_\@:
	.pushsection .discard.unwind_hints
	/* struct unwind_hint */
	.long .Lunwind_hint_ip_\@ - .
	.short \sp_offset
	.byte \sp_reg
	.byte \sp_ptregs
	.byte \ra_reg
	.byte \clear
	.byte \skip
	.balign 4
	.popsection
#endif
	.endm

	.macro UNWIND_HINT_SKIP
	UNWIND_HINT clear=1 skip=1
	.endm

	.macro UNWIND_HINT_DEAD_END
#ifdef CONFIG_STACK_VALIDATION
0:	nopr
	.pushsection .discard.unreachable
	.long 0b - .
	.popsection
#endif
	.endm

#endif /* __ASSEMBLY__ */

#endif /* _ASM_S390_UNWIND_HINTS_H */
