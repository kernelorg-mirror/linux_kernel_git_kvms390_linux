// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#ifndef _OBJTOOL_CFI_H
#define _OBJTOOL_CFI_H

#define REG_IGNORE	-2
#define REG_UNDEF	-1
#define REG_ORIG_R0	0
#define REG_ORIG_R1	1
#define REG_ORIG_R2	2
#define REG_ORIG_R3	3
#define REG_ORIG_R4	4
#define REG_ORIG_R5	5
#define REG_ORIG_R6	6
#define REG_ORIG_R7	7
#define REG_ORIG_R8	8
#define REG_ORIG_R9	9
#define REG_ORIG_R10	10
#define REG_ORIG_R11	11
#define REG_ORIG_R12	12
#define REG_ORIG_R13	13
#define REG_ORIG_R14	14
#define REG_ORIG_R15	15
#define REG_PTREGS	16
#define REG_CONST	17
#define REG_ADDR	18
#define REG_TABLE	19
#define REG_INSN_ADDR	20

#define REG_RA		REG_ORIG_R14
#define REG_CFA		REG_ORIG_R15

struct cfi_reg {
	int base;
	union {
		long offset;
		void *ptr;
	};
};

#define CFI_R0		0
#define CFI_R1		1
#define CFI_R2		2
#define CFI_R3		3
#define CFI_R4		4
#define CFI_R5		5
#define CFI_R6		6
#define CFI_R7		7
#define CFI_R8		8
#define CFI_R9		9
#define CFI_R10		10
#define CFI_R11		11
#define CFI_R12		12
#define CFI_R13		13
#define CFI_R14		14
#define CFI_R15		15
#define CFI_NUM_REGS	16

#endif /* _OBJTOOL_CFI_H */
