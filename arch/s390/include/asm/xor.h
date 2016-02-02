/*
 * Optimited xor routines
 *
 * Copyright IBM Corp. 2016
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#ifndef _ASM_S390_XOR_H
#define _ASM_S390_XOR_H

void xor_xc_2(unsigned long, unsigned long *, unsigned long *);
void xor_xc_3(unsigned long, unsigned long *, unsigned long *,
	      unsigned long *);
void xor_xc_4(unsigned long, unsigned long *, unsigned long *,
	      unsigned long *, unsigned long *);
void xor_xc_5(unsigned long, unsigned long *, unsigned long *,
	      unsigned long *, unsigned long *, unsigned long *);

static struct xor_block_template xor_block_xc = {
	.name = "xc",
	.do_2 = xor_xc_2,
	.do_3 = xor_xc_3,
	.do_4 = xor_xc_4,
	.do_5 = xor_xc_5,
};

#undef XOR_TRY_TEMPLATES
#define XOR_TRY_TEMPLATES				\
do {							\
	xor_speed(&xor_block_xc);			\
} while (0)

#define XOR_SELECT_TEMPLATE(FASTEST)	&xor_block_xc

#endif /* _ASM_S390_XOR_H */
