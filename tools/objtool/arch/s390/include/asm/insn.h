// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#ifndef _ASM_S390_INSN_H
#define _ASM_S390_INSN_H

static inline int insn_length(unsigned char *code)
{
	return ((((int) *code + 64) >> 7) + 1) << 1;
}

void *insn_find(unsigned char *code);
unsigned int insn_get_tag(void *pinsn);
void insn_operand_values(void *pinsn, unsigned char *code,
			 unsigned int *values);

#endif /* _ASM_S390_INSN_H */
