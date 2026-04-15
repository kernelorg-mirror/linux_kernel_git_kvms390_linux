/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_S390_SAE_ASM_H
#define __ASM_S390_SAE_ASM_H

#ifdef __ASSEMBLER__

.macro	GPR_NUM	opd gr
	\opd = 255
	.irp rs,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	.ifc \gr,%r\rs
		\opd = \rs
	.endif
	.endr
	.if \opd == 255
		\opd = \gr
	.endif
.endm

/*
 * RIE_H - RIE-h instruction format
 *
 * RIE-h format: <insn> R1, R3, I2, M4
 *    +--------+----+----+----+-----------------+----+--------+
 *    | OpCode | R1 |////| R3 |        I2       | M4 | Opcode |
 *    +--------+----+----+----+-----------------+----+--------+
 *    0        8    12   16   20                36   40      47
 */
.macro RIE_H	opc, gr1, gr3, imm2, m4
	GPR_NUM	r1, \gr1
	GPR_NUM	r3, \gr3
	.byte	(\opc & 0xff00) >> 8
	.byte	r1 << 4
	.byte	(r3 << 4) | ((\imm2 & 0xf000) >> 12)
	.byte	((\imm2 & 0x0ff0) >> 4)
	.byte	((\imm2 & 0x000f) << 4) | (\m4 & 0xf)
	.byte	\opc & 0xff
.endm

.macro SASR r1, r3, i2, m4
	RIE_H 0xed99, \r1, \r3, \i2, \m4,
.endm

.macro EASR r1, r3, i2, m4
	RIE_H 0xed9b, \r1, \r3, \i2, \m4,
.endm

#endif /* __ASSEMBLER__ */
#endif /* __ASM_S390_SAE_ASM_H */
