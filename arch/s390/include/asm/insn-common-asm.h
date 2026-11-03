/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Assembler helper macros to generate .byte/.word code for instructions
 * that are unknown to older binutils versions.
 */

#ifndef __ASM_S390_INSN_COMMON_ASM_H
#define __ASM_S390_INSN_COMMON_ASM_H

#ifdef __ASSEMBLER__

.macro	RANGECHECK	min max val
	.if (\val < \min) || (\val > \max)
	.error "operand out of range (\val is not between \min and \max)"
	.endif
.endm

.macro	ASSERT_U16	val
	RANGECHECK 0, 65535, \val
.endm

.macro	ASSERT_S16	val
	RANGECHECK -32768, 32767, \val
.endm

.macro	ASSERT_U8	val
	RANGECHECK 0, 255, \val
.endm

.macro	ASSERT_U4	val
	RANGECHECK 0, 15, \val
.endm

.macro	ASSERT_U5	val
	RANGECHECK 0, 31, \val
.endm

/*
 * GR_NUM - Retrieve general-purpose register number
 *
 * @opd:	Operand to store register number
 * @gr:		String designation register in the format "%rN"
 */
.macro	GR_NUM	opd gr
	\opd = 255
	.irp rs,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	.ifc \gr,%r\rs
		\opd = \rs
	.endif
	.endr
	.if \opd == 255
		\opd = \gr
		ASSERT_U4	\opd
	.endif
.endm

/*
 * VX_NUM - Retrieve vector register number
 *
 * @opd:	Operand to store register number
 * @vxr:	String designation register in the format "%vN"
 *
 * The vector register number is used for as input number to the
 * instruction and, as well as, to compute the RXB field of the
 * instruction.
 */
.macro	VX_NUM	opd vxr
	\opd = 255
	.irp vs,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	.ifc \vxr,%v\vs
		\opd = \vs
	.endif
	.endr
	.if \opd == 255
		\opd = \vxr
		ASSERT_U5	\opd
	.endif
.endm

#endif	/* __ASSEMBLER__ */
#endif	/* __ASM_S390_INSN_COMMON_ASM_H */
