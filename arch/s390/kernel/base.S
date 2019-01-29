/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  arch/s390/kernel/base.S
 *
 *    Copyright IBM Corp. 2006, 2007
 *    Author(s): Heiko Carstens <heiko.carstens@de.ibm.com>
 *		 Michael Holzheu <holzheu@de.ibm.com>
 */

#include <linux/compiler.h>
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/nospec-insn.h>
#include <asm/ptrace.h>
#include <asm/sigp.h>
#include <asm/unwind_hints.h>

	GEN_BR_THUNK %r9
	GEN_BR_THUNK %r14

ENTRY(s390_base_mcck_handler)
	UNWIND_HINT_SKIP
	lg	%r15,__LC_NODAT_STACK	# load panic stack
	aghi	%r15,-STACK_FRAME_OVERHEAD
	larl	%r1,s390_base_mcck_handler_fn
	lg	%r9,0(%r1)
	ltgr	%r9,%r9
	jz	1f
	BASR_EX	%r14,%r9
1:	la	%r1,4095
	lmg	%r0,%r15,__LC_GPREGS_SAVE_AREA-4095(%r1)
	UNWIND_HINT_SKIP
	lpswe	__LC_MCK_OLD_PSW
	UNWIND_HINT_DEAD_END
ENDPROC(s390_base_mcck_handler)

	.section .bss
	.align 8
	.globl	s390_base_mcck_handler_fn
s390_base_mcck_handler_fn:
	.quad	0
	.previous

ENTRY(s390_base_ext_handler)
	UNWIND_HINT_SKIP
	stmg	%r0,%r15,__LC_SAVE_AREA_ASYNC
	aghi	%r15,-STACK_FRAME_OVERHEAD
	larl	%r1,s390_base_ext_handler_fn
	lg	%r9,0(%r1)
	ltgr	%r9,%r9
	jz	1f
	BASR_EX	%r14,%r9
1:	lmg	%r0,%r15,__LC_SAVE_AREA_ASYNC
	ni	__LC_EXT_OLD_PSW+1,0xfd	# clear wait state bit
	lpswe	__LC_EXT_OLD_PSW
	UNWIND_HINT_DEAD_END
ENDPROC(s390_base_ext_handler)

	.section .bss
	.align 8
	.globl s390_base_ext_handler_fn
s390_base_ext_handler_fn:
	.quad	0
	.previous

ENTRY(s390_base_pgm_handler)
	UNWIND_HINT_SKIP
	stmg	%r0,%r15,__LC_SAVE_AREA_SYNC
	larl	%r13,disabled_wait_psw
	aghi	%r15,-STACK_FRAME_OVERHEAD
	larl	%r1,s390_base_pgm_handler_fn
	lg	%r9,0(%r1)
	ltgr	%r9,%r9
	jz	1f
	BASR_EX	%r14,%r9
	lmg	%r0,%r15,__LC_SAVE_AREA_SYNC
	lpswe	__LC_PGM_OLD_PSW
1:	lpswe	0(%r13)
	UNWIND_HINT_DEAD_END
ENDPROC(s390_base_pgm_handler)

	.section .rodata, "a"
	.align	8
disabled_wait_psw:
	.quad	0x0002000180000000,0x0000000000000000 + s390_base_pgm_handler
	.previous

	.section .bss
	.align 8
	.globl s390_base_pgm_handler_fn
s390_base_pgm_handler_fn:
	.quad	0
	.previous
