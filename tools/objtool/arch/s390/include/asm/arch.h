/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#ifndef _ARCH_H
#define _ARCH_H

#include <stdbool.h>
#include <linux/list.h>
#include <asm/cfi.h>
#include <elfdefs.h>

#define INSN_NOP		1
#define INSN_BRANCH_INDIRECT	2
#define INSN_BRANCH_RELATIVE	3
#define INSN_BRANCH_EXPOLINE	4
#define INSN_BAS		5	/* branch (indirect) and save */
#define INSN_BRAS		6	/* branch relative and save */
#define INSN_EX			7	/* execute (indirect) */
#define INSN_EXRL		8	/* execute relative */
#define INSN_MEM_ADD		9
#define INSN_MEM_LOAD		10
#define INSN_MEM_STORE		11
#define INSN_REG_ADDR		12
#define INSN_REG_CONST		13		/* rx = const */
#define INSN_REG_ADD1		14		/* rx = ry + const */
#define INSN_REG_ADD2		15		/* rx = ry + rz + const */
#define INSN_REG_SUB2		16		/* rx = ry - rz + const */
#define INSN_BUG		17
#define INSN_OTHER		18
#define INSN_LAST		INSN_OTHER

struct operands {
	unsigned char r1, r2;
	int offset, length;
};

struct insn_ops {
	struct operands dest;
	struct operands src;
	unsigned int conditional;
	unsigned short clobber;
};

#define BUGFLAG_WARNING		(1 << 0)

struct bug_entry {
	signed int	bug_addr_disp;
	unsigned short	flags;
};

struct bug_entry_verbose {
	signed int	bug_addr_disp;
	signed int	file_disp;
	unsigned short	line;
	unsigned short	flags;
};

int arch_decode_instruction(struct elf *elf, struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, unsigned char *type,
			    struct insn_ops *op);

#endif /* _ARCH_H */
