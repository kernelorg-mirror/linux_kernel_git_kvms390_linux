/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_S390_SAE_ASM_H
#define __ASM_S390_SAE_ASM_H

#ifndef __ASM_S390_SAE_H
#error only <asm/sae.h> can be included directly
#endif

#include <asm/insn-common-asm.h>

#ifdef __ASSEMBLER__

/*
 * INSN_RIE_H - RIE-h instruction format
 *
 * RIE-h format: <insn> R1, R3, I2, M4
 *    +--------+----+----+----+-----------------+----+--------+
 *    | OpCode | R1 |////| R3 |        I2       | M4 | Opcode |
 *    +--------+----+----+----+-----------------+----+--------+
 *    0        8    12   16   20                36   40      47
 */
.macro	INSN_RIE_H	opc, gr1, gr3, imm2, m4
	GR_NUM	r1, \gr1
	GR_NUM	r3, \gr3
	ASSERT_U16	\opc
	ASSERT_U16	\imm2
	ASSERT_U4	\m4
	.byte	(\opc & 0xff00) >> 8
	.byte	r1 << 4
	.byte	(r3 << 4) | ((\imm2 & 0xf000) >> 12)
	.byte	((\imm2 & 0x0ff0) >> 4)
	.byte	((\imm2 & 0x000f) << 4) | (\m4 & 0xf)
	.byte	\opc & 0xff
.endm

.macro	SASR	r1, r3, i2, m4
	INSN_RIE_H 0xed99, \r1, \r3, \i2, \m4
.endm

.macro	EASR	r1, r3, i2, m4
	INSN_RIE_H 0xed9b, \r1, \r3, \i2, \m4
.endm

#endif /* __ASSEMBLER__ */
#endif /* __ASM_S390_SAE_ASM_H */
